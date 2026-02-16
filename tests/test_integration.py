"""Integration tests for vault-cli complete workflows."""

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

# Import fixtures from conftest


class TestFullWorkflow:
    """End-to-end integration tests."""

    def test_complete_workflow(
        self, temp_vault_dir, test_vault, mock_daemon_dir, mock_pid_tree
    ):
        """Test complete workflow: agent -> get -> lock."""
        from vault_cli.daemon import VaultDaemon, send_request
        from vault_cli import daemon as daemon_module

        # Start daemon
        vault_daemon = VaultDaemon(test_vault["path"], foreground=True)
        vault_daemon.session_store = __import__("vault_cli.session", fromlist=["SessionStore"]).SessionStore()
        vault_daemon.audit_logger = __import__("vault_cli.audit", fromlist=["AuditLogger"]).AuditLogger(
            mock_daemon_dir / "access.log"
        )
        vault_daemon.lock = threading.Lock()
        vault_daemon._create_socket()
        vault_daemon.running = True

        # Start daemon in background thread
        def run_daemon():
            import socket as sock
            while vault_daemon.running:
                try:
                    conn, _ = vault_daemon.socket.accept()
                    thread = threading.Thread(target=vault_daemon._handle_connection, args=(conn,))
                    thread.daemon = True
                    thread.start()
                except sock.timeout:
                    continue
                except OSError:
                    break

        daemon_thread = threading.Thread(target=run_daemon)
        daemon_thread.daemon = True
        daemon_thread.start()

        time.sleep(0.1)

        try:
            # Create session (simulate vault agent)
            create_response = send_request({
                "request_id": "test-create",
                "action": "create_session",
                "payload": {
                    "password": test_vault["password"],
                    "scope": ["work/*"],
                    "ttl": 3600,
                    "root_pid": 1000,
                    "command": "claude"
                }
            })

            assert create_response["status"] == "ok"
            session_id = create_response["data"]["session_id"]

            # Get secret within scope
            get_response = send_request({
                "request_id": "test-get",
                "action": "get",
                "session_id": session_id,
                "payload": {
                    "path": "work/api/key",
                    "client_pid": 1000
                }
            })

            assert get_response["status"] == "ok"
            assert get_response["data"]["secret"] == "sk_live_work_123"

            # Get secret outside scope (should fail)
            denied_response = send_request({
                "request_id": "test-denied",
                "action": "get",
                "session_id": session_id,
                "payload": {
                    "path": "personal/email/password",
                    "client_pid": 1000
                }
            })

            assert denied_response["status"] == "error"
            assert denied_response["error"]["code"] == "ACCESS_DENIED"

            # Lock (destroy session)
            lock_response = send_request({
                "request_id": "test-lock",
                "action": "destroy_session",
                "payload": {"session_id": session_id}
            })

            assert lock_response["status"] == "ok"

            # Verify session is gone
            list_response = send_request({
                "request_id": "test-list",
                "action": "list_sessions"
            })

            assert list_response["status"] == "ok"
            assert len(list_response["data"]["sessions"]) == 0

        finally:
            vault_daemon.running = False
            if vault_daemon.socket:
                vault_daemon.socket.close()

    def test_scope_enforcement(self, temp_vault_dir, test_vault, mock_daemon_dir, mock_pid_tree):
        """Test that scope patterns are enforced correctly."""
        from vault_cli.daemon import send_request
        from vault_cli.session import SessionStore, Session
        from vault_cli.audit import AuditLogger
        import socket as sock
        import threading

        # Setup daemon
        from vault_cli.daemon import VaultDaemon
        vault_daemon = VaultDaemon(test_vault["path"], foreground=True)
        vault_daemon.session_store = SessionStore()
        vault_daemon.audit_logger = AuditLogger(mock_daemon_dir / "access.log")
        vault_daemon.lock = threading.Lock()
        vault_daemon._create_socket()
        vault_daemon.running = True

        def run_daemon():
            while vault_daemon.running:
                try:
                    conn, _ = vault_daemon.socket.accept()
                    thread = threading.Thread(target=vault_daemon._handle_connection, args=(conn,))
                    thread.daemon = True
                    thread.start()
                except sock.timeout:
                    continue
                except OSError:
                    break

        daemon_thread = threading.Thread(target=run_daemon)
        daemon_thread.daemon = True
        daemon_thread.start()
        time.sleep(0.1)

        try:
            # Create session with specific scope
            create_response = send_request({
                "request_id": "test",
                "action": "create_session",
                "payload": {
                    "password": test_vault["password"],
                    "scope": ["work/api/*", "test/*"],
                    "ttl": 3600,
                    "root_pid": 1000,
                    "command": "claude"
                }
            })

            assert create_response["status"] == "ok"
            session_id = create_response["data"]["session_id"]

            # Should work: work/api/key matches work/api/*
            assert send_request({
                "request_id": "test",
                "action": "get",
                "session_id": session_id,
                "payload": {"path": "work/api/key", "client_pid": 1000}
            })["status"] == "ok"

            # Should fail: work/db/password doesn't match work/api/*
            assert send_request({
                "request_id": "test",
                "action": "get",
                "session_id": session_id,
                "payload": {"path": "work/db/password", "client_pid": 1000}
            })["status"] == "error"

            # Should work: test/anything matches test/*
            assert send_request({
                "request_id": "test",
                "action": "get",
                "session_id": session_id,
                "payload": {"path": "test/secret", "client_pid": 1000}
            })["status"] == "ok"

        finally:
            vault_daemon.running = False
            if vault_daemon.socket:
                vault_daemon.socket.close()

    def test_session_expiration(self, temp_vault_dir, test_vault, mock_daemon_dir, mock_pid_tree, mock_time):
        """Test that sessions expire after TTL."""
        from vault_cli.daemon import send_request
        from vault_cli.session import SessionStore
        from vault_cli.audit import AuditLogger
        from vault_cli import session as session_module
        import socket as sock
        import threading

        # Setup daemon with mocked time
        from vault_cli.daemon import VaultDaemon
        vault_daemon = VaultDaemon(test_vault["path"], foreground=True)
        vault_daemon.session_store = SessionStore()
        vault_daemon.audit_logger = AuditLogger(mock_daemon_dir / "access.log")
        vault_daemon.lock = threading.Lock()
        vault_daemon._create_socket()
        vault_daemon.running = True

        def run_daemon():
            while vault_daemon.running:
                try:
                    conn, _ = vault_daemon.socket.accept()
                    thread = threading.Thread(target=vault_daemon._handle_connection, args=(conn,))
                    thread.daemon = True
                    thread.start()
                except sock.timeout:
                    continue
                except OSError:
                    break

        daemon_thread = threading.Thread(target=run_daemon)
        daemon_thread.daemon = True
        daemon_thread.start()
        time.sleep(0.1)

        try:
            # Create session with 10 second TTL
            create_response = send_request({
                "request_id": "test",
                "action": "create_session",
                "payload": {
                    "password": test_vault["password"],
                    "scope": ["*"],
                    "ttl": 10,
                    "root_pid": 1000,
                    "command": "claude"
                }
            })

            assert create_response["status"] == "ok"
            session_id = create_response["data"]["session_id"]

            # Should work immediately
            assert send_request({
                "request_id": "test",
                "action": "get",
                "session_id": session_id,
                "payload": {"path": "work/api/key", "client_pid": 1000}
            })["status"] == "ok"

            # Advance time past expiration
            mock_time[0] += 15

            # Should fail - session expired
            response = send_request({
                "request_id": "test",
                "action": "get",
                "session_id": session_id,
                "payload": {"path": "work/api/key", "client_pid": 1000}
            })

            assert response["status"] == "error"
            assert response["error"]["code"] == "NO_SESSION"

        finally:
            vault_daemon.running = False
            if vault_daemon.socket:
                vault_daemon.socket.close()

    def test_concurrent_sessions(self, temp_vault_dir, test_vault, mock_daemon_dir, mock_pid_tree):
        """Test that multiple sessions work independently."""
        from vault_cli.daemon import send_request
        from vault_cli.session import SessionStore
        from vault_cli.audit import AuditLogger
        import socket as sock
        import threading

        # Setup daemon
        from vault_cli.daemon import VaultDaemon
        vault_daemon = VaultDaemon(test_vault["path"], foreground=True)
        vault_daemon.session_store = SessionStore()
        vault_daemon.audit_logger = AuditLogger(mock_daemon_dir / "access.log")
        vault_daemon.lock = threading.Lock()
        vault_daemon._create_socket()
        vault_daemon.running = True

        def run_daemon():
            while vault_daemon.running:
                try:
                    conn, _ = vault_daemon.socket.accept()
                    thread = threading.Thread(target=vault_daemon._handle_connection, args=(conn,))
                    thread.daemon = True
                    thread.start()
                except sock.timeout:
                    continue
                except OSError:
                    break

        daemon_thread = threading.Thread(target=run_daemon)
        daemon_thread.daemon = True
        daemon_thread.start()
        time.sleep(0.1)

        try:
            # Create two sessions with different scopes
            session1 = send_request({
                "request_id": "test",
                "action": "create_session",
                "payload": {
                    "password": test_vault["password"],
                    "scope": ["work/*"],
                    "ttl": 3600,
                    "root_pid": 1000,
                    "command": "claude"
                }
            })["data"]["session_id"]

            session2 = send_request({
                "request_id": "test",
                "action": "create_session",
                "payload": {
                    "password": test_vault["password"],
                    "scope": ["personal/*"],
                    "ttl": 3600,
                    "root_pid": 2000,
                    "command": "python"
                }
            })["data"]["session_id"]

            # Session 1 can access work/*
            assert send_request({
                "request_id": "test",
                "action": "get",
                "session_id": session1,
                "payload": {"path": "work/api/key", "client_pid": 1000}
            })["status"] == "ok"

            # Session 1 cannot access personal/*
            assert send_request({
                "request_id": "test",
                "action": "get",
                "session_id": session1,
                "payload": {"path": "personal/email/password", "client_pid": 1000}
            })["status"] == "error"

            # Session 2 can access personal/*
            assert send_request({
                "request_id": "test",
                "action": "get",
                "session_id": session2,
                "payload": {"path": "personal/email/password", "client_pid": 2000}
            })["status"] == "ok"

            # Session 2 cannot access work/*
            assert send_request({
                "request_id": "test",
                "action": "get",
                "session_id": session2,
                "payload": {"path": "work/api/key", "client_pid": 2000}
            })["status"] == "error"

            # Revoke session 1 only
            send_request({
                "request_id": "test",
                "action": "destroy_session",
                "payload": {"session_id": session1}
            })

            # Session 1 is gone
            assert send_request({
                "request_id": "test",
                "action": "get",
                "session_id": session1,
                "payload": {"path": "work/api/key", "client_pid": 1000}
            })["status"] == "error"

            # Session 2 still works
            assert send_request({
                "request_id": "test",
                "action": "get",
                "session_id": session2,
                "payload": {"path": "personal/email/password", "client_pid": 2000}
            })["status"] == "ok"

        finally:
            vault_daemon.running = False
            if vault_daemon.socket:
                vault_daemon.socket.close()


class TestEnvMigration:
    """Tests for env migration functionality."""

    def test_migrate_env_creates_entries(self, temp_vault_dir, test_vault, mock_daemon_dir, mock_pid_tree):
        """Test that migrate-env creates vault entries."""
        from vault_cli.daemon import send_request
        from vault_cli.session import SessionStore
        from vault_cli.audit import AuditLogger
        import socket as sock
        import threading

        # Setup daemon
        from vault_cli.daemon import VaultDaemon
        vault_daemon = VaultDaemon(test_vault["path"], foreground=True)
        vault_daemon.session_store = SessionStore()
        vault_daemon.audit_logger = AuditLogger(mock_daemon_dir / "access.log")
        vault_daemon.lock = threading.Lock()
        vault_daemon._create_socket()
        vault_daemon.running = True

        def run_daemon():
            while vault_daemon.running:
                try:
                    conn, _ = vault_daemon.socket.accept()
                    thread = threading.Thread(target=vault_daemon._handle_connection, args=(conn,))
                    thread.daemon = True
                    thread.start()
                except sock.timeout:
                    continue
                except OSError:
                    break

        daemon_thread = threading.Thread(target=run_daemon)
        daemon_thread.daemon = True
        daemon_thread.start()
        time.sleep(0.1)

        try:
            # Create session
            session_id = send_request({
                "request_id": "test",
                "action": "create_session",
                "payload": {
                    "password": test_vault["password"],
                    "scope": ["migrated/*"],
                    "ttl": 3600,
                    "root_pid": 1000,
                    "command": "bash"
                }
            })["data"]["session_id"]

            # Create .env file
            env_file = temp_vault_dir / ".env"
            env_file.write_text("""DATABASE_URL=postgres://user:pass@localhost/db
API_KEY=sk_live_123456
SECRET_KEY=super_secret
# Comment line
""")

            # Migrate env file
            with open(env_file, "r") as f:
                content = f.read()

            # Parse and migrate
            import re
            env_pattern = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$')
            entries = []

            for line in content.split("\n"):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                match = env_pattern.match(line)
                if match:
                    key = match.group(1)
                    value = match.group(2)

                    response = send_request({
                        "request_id": f"migrate-{key}",
                        "action": "add",
                        "session_id": session_id,
                        "payload": {
                            "path": f"migrated/{key.lower()}",
                            "secret": value,
                            "note": f"Migrated from .env:{key}",
                            "client_pid": 1000
                        }
                    })

                    if response["status"] == "ok":
                        entries.append(key)

            assert len(entries) == 3

            # Verify entries were created
            for key in ["database_url", "api_key", "secret_key"]:
                response = send_request({
                    "request_id": "test",
                    "action": "get",
                    "session_id": session_id,
                    "payload": {"path": f"migrated/{key}", "client_pid": 1000}
                })
                assert response["status"] == "ok"

        finally:
            vault_daemon.running = False
            if vault_daemon.socket:
                vault_daemon.socket.close()


class TestLegacySessionFallback:
    """Tests for backward compatibility with legacy session file."""

    def test_legacy_session_still_works(self, temp_vault_dir, test_vault):
        """Test that legacy session file is still supported."""
        import base64
        from vault_cli.main import load_session
        import vault_cli.main as main_module

        # Create legacy session file
        future_time = datetime.now(timezone.utc).timestamp() + 3600
        session = {
            'key': base64.b64encode(test_vault["key"]).decode('utf-8'),
            'expires': datetime.fromtimestamp(future_time, tz=timezone.utc).isoformat()
        }

        # Create temp session file
        temp_session = temp_vault_dir / ".vault-session"
        with open(temp_session, 'w') as f:
            json.dump(session, f)

        # Temporarily set session file path
        original = main_module.SESSION_FILE
        main_module.SESSION_FILE = temp_session

        try:
            # Load session
            key = load_session()
            assert key is not None
            assert key == test_vault["key"]
        finally:
            main_module.SESSION_FILE = original


class TestAuditLogging:
    """Tests for audit logging in workflows."""

    def test_access_logged(self, temp_vault_dir, test_vault, mock_daemon_dir, mock_pid_tree):
        """Test that accesses are logged."""
        from vault_cli.daemon import send_request
        from vault_cli.session import SessionStore
        from vault_cli.audit import AuditLogger
        import socket as sock
        import threading

        # Setup daemon
        from vault_cli.daemon import VaultDaemon
        vault_daemon = VaultDaemon(test_vault["path"], foreground=True)
        vault_daemon.session_store = SessionStore()
        vault_daemon.audit_logger = AuditLogger(mock_daemon_dir / "access.log")
        vault_daemon.lock = threading.Lock()
        vault_daemon._create_socket()
        vault_daemon.running = True

        def run_daemon():
            while vault_daemon.running:
                try:
                    conn, _ = vault_daemon.socket.accept()
                    thread = threading.Thread(target=vault_daemon._handle_connection, args=(conn,))
                    thread.daemon = True
                    thread.start()
                except sock.timeout:
                    continue
                except OSError:
                    break

        daemon_thread = threading.Thread(target=run_daemon)
        daemon_thread.daemon = True
        daemon_thread.start()
        time.sleep(0.1)

        try:
            # Create session
            session_id = send_request({
                "request_id": "test",
                "action": "create_session",
                "payload": {
                    "password": test_vault["password"],
                    "scope": ["work/*"],
                    "ttl": 3600,
                    "root_pid": 1000,
                    "command": "claude"
                }
            })["data"]["session_id"]

            # Access allowed
            send_request({
                "request_id": "test",
                "action": "get",
                "session_id": session_id,
                "payload": {"path": "work/api/key", "client_pid": 1000}
            })

            # Access denied
            send_request({
                "request_id": "test",
                "action": "get",
                "session_id": session_id,
                "payload": {"path": "personal/email/password", "client_pid": 1000}
            })

            # Check logs
            recent = vault_daemon.audit_logger.read_recent(10)
            log_text = " ".join(recent)

            assert "ALLOWED" in log_text
            assert "DENIED" in log_text
            assert "work/api/key" in log_text
            assert "personal/email/password" in log_text

        finally:
            vault_daemon.running = False
            if vault_daemon.socket:
                vault_daemon.socket.close()


class TestDaemonStop:
    """Tests for daemon stop command."""

    def test_stop_daemon(self, temp_vault_dir, monkeypatch):
        """Test stopping the daemon."""
        from vault_cli.daemon import VaultDaemon
        from vault_cli import daemon as daemon_module

        daemon_dir = temp_vault_dir / ".vault"
        daemon_dir.mkdir(parents=True, exist_ok=True)

        monkeypatch.setattr(daemon_module, "PID_FILE", daemon_dir / "daemon.pid")

        # Create a subprocess that we can actually kill
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        (daemon_dir / "daemon.pid").write_text(str(proc.pid))

        d = VaultDaemon(temp_vault_dir / "test.vault")

        try:
            result = d.stop()
            assert result is True
            # Process should be terminated
            proc.wait(timeout=1)
        except:
            proc.kill()
