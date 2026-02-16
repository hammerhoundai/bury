"""Unit tests for daemon module."""

import json
import os
import signal
import socket as sock
import threading
import time
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

import pytest

from vault_cli import daemon


class TestVaultDaemonInit:
    """Tests for VaultDaemon initialization."""

    def test_daemon_init(self, temp_vault_dir):
        """Test daemon initialization."""
        vault_path = temp_vault_dir / "test.vault"
        d = daemon.VaultDaemon(vault_path, foreground=False)

        assert d.vault_path == vault_path
        assert d.foreground is False
        assert d.running is False

    def test_daemon_init_foreground(self, temp_vault_dir):
        """Test daemon init with foreground mode."""
        vault_path = temp_vault_dir / "test.vault"
        d = daemon.VaultDaemon(vault_path, foreground=True)

        assert d.foreground is True


class TestDaemonLifecycle:
    """Tests for daemon start/stop."""

    def test_is_running_no_pid_file(self, temp_vault_dir, monkeypatch):
        """Test is_running when no PID file exists."""
        daemon_dir = temp_vault_dir / ".vault"
        monkeypatch.setattr(daemon, "PID_FILE", daemon_dir / "daemon.pid")

        d = daemon.VaultDaemon(temp_vault_dir / "test.vault")
        assert d._is_running() is False

    def test_is_running_with_stale_pid_file(self, temp_vault_dir, monkeypatch):
        """Test is_running with stale PID file."""
        daemon_dir = temp_vault_dir / ".vault"
        daemon_dir.mkdir(parents=True, exist_ok=True)

        monkeypatch.setattr(daemon, "PID_FILE", daemon_dir / "daemon.pid")
        monkeypatch.setattr(daemon, "SOCKET_PATH", daemon_dir / "daemon.sock")

        # Write non-existent PID
        (daemon_dir / "daemon.pid").write_text("99999")

        d = daemon.VaultDaemon(temp_vault_dir / "test.vault")
        assert d._is_running() is False
        # Should clean up stale file
        assert not (daemon_dir / "daemon.pid").exists()

    def test_read_pid_valid(self, temp_vault_dir, monkeypatch):
        """Test reading valid PID."""
        daemon_dir = temp_vault_dir / ".vault"
        daemon_dir.mkdir(parents=True, exist_ok=True)

        monkeypatch.setattr(daemon, "PID_FILE", daemon_dir / "daemon.pid")
        (daemon_dir / "daemon.pid").write_text("12345")

        d = daemon.VaultDaemon(temp_vault_dir / "test.vault")
        assert d._read_pid() == 12345

    def test_read_pid_empty_file(self, temp_vault_dir, monkeypatch):
        """Test reading empty PID file."""
        daemon_dir = temp_vault_dir / ".vault"
        daemon_dir.mkdir(parents=True, exist_ok=True)

        monkeypatch.setattr(daemon, "PID_FILE", daemon_dir / "daemon.pid")
        (daemon_dir / "daemon.pid").write_text("")

        d = daemon.VaultDaemon(temp_vault_dir / "test.vault")
        assert d._read_pid() is None

    def test_write_pid(self, temp_vault_dir, monkeypatch):
        """Test writing PID file."""
        daemon_dir = temp_vault_dir / ".vault"
        daemon_dir.mkdir(parents=True, exist_ok=True)

        monkeypatch.setattr(daemon, "PID_FILE", daemon_dir / "daemon.pid")

        d = daemon.VaultDaemon(temp_vault_dir / "test.vault")
        d._write_pid()

        pid = int((daemon_dir / "daemon.pid").read_text())
        assert pid == os.getpid()
        assert oct((daemon_dir / "daemon.pid").stat().st_mode)[-3:] == "600"

    def test_cleanup_files(self, temp_vault_dir, monkeypatch):
        """Test cleanup of socket and PID files."""
        daemon_dir = temp_vault_dir / ".vault"
        daemon_dir.mkdir(parents=True, exist_ok=True)

        monkeypatch.setattr(daemon, "PID_FILE", daemon_dir / "daemon.pid")
        monkeypatch.setattr(daemon, "SOCKET_PATH", daemon_dir / "daemon.sock")

        (daemon_dir / "daemon.pid").write_text("12345")
        (daemon_dir / "daemon.sock").write_text("")

        d = daemon.VaultDaemon(temp_vault_dir / "test.vault")
        d._cleanup_files()

        assert not (daemon_dir / "daemon.pid").exists()
        assert not (daemon_dir / "daemon.sock").exists()


class TestPingDaemon:
    """Tests for ping_daemon function."""

    def test_ping_daemon_not_running(self, temp_vault_dir, monkeypatch):
        """Test ping when daemon not running."""
        daemon_dir = temp_vault_dir / ".vault"
        monkeypatch.setattr(daemon, "SOCKET_PATH", daemon_dir / "daemon.sock")

        assert daemon.ping_daemon() is False

    def test_ping_daemon_with_mock_socket(self, temp_vault_dir, monkeypatch):
        """Test ping with mock socket."""
        daemon_dir = temp_vault_dir / ".vault"
        daemon_dir.mkdir(parents=True, exist_ok=True)

        monkeypatch.setattr(daemon, "SOCKET_PATH", daemon_dir / "daemon.sock")

        # Create a mock socket server
        server = sock.socket(sock.AF_UNIX, sock.SOCK_STREAM)
        server.bind(str(daemon_dir / "daemon.sock"))
        server.listen(1)
        server.settimeout(1.0)

        def respond():
            try:
                conn, _ = server.accept()
                data = conn.recv(1024)
                if data:
                    response = json.dumps({"status": "ok", "data": {"version": "2.0.0"}})
                    conn.sendall((response + "\n").encode())
                conn.close()
            except sock.timeout:
                pass

        thread = threading.Thread(target=respond)
        thread.daemon = True
        thread.start()

        result = daemon.ping_daemon()

        server.close()
        assert result is True


class TestSendRequest:
    """Tests for send_request function."""

    def test_send_request_daemon_not_running(self, temp_vault_dir, monkeypatch):
        """Test send when daemon not running."""
        daemon_dir = temp_vault_dir / ".vault"
        monkeypatch.setattr(daemon, "SOCKET_PATH", daemon_dir / "daemon.sock")

        response = daemon.send_request({"action": "ping"})

        assert response["status"] == "error"
        assert response["error"]["code"] == "DAEMON_NOT_RUNNING"

    def test_send_request_success(self, temp_vault_dir, monkeypatch):
        """Test successful request/response."""
        daemon_dir = temp_vault_dir / ".vault"
        daemon_dir.mkdir(parents=True, exist_ok=True)

        monkeypatch.setattr(daemon, "SOCKET_PATH", daemon_dir / "daemon.sock")

        # Create mock server
        server = sock.socket(sock.AF_UNIX, sock.SOCK_STREAM)
        server.bind(str(daemon_dir / "daemon.sock"))
        server.listen(1)
        server.settimeout(2.0)

        def respond():
            try:
                conn, _ = server.accept()
                data = conn.recv(4096)
                if data:
                    response = {"request_id": "test", "status": "ok", "data": {"result": "success"}}
                    conn.sendall((json.dumps(response) + "\n").encode())
                conn.close()
            except sock.timeout:
                pass

        thread = threading.Thread(target=respond)
        thread.daemon = True
        thread.start()

        response = daemon.send_request({"request_id": "test", "action": "test"})

        server.close()
        assert response["status"] == "ok"
        assert response["data"]["result"] == "success"


class TestDaemonSocketCreation:
    """Tests for socket creation."""

    def test_create_socket(self, temp_vault_dir, test_vault, monkeypatch):
        """Test socket creation."""
        daemon_dir = temp_vault_dir / ".vault"
        daemon_dir.mkdir(parents=True, exist_ok=True)

        monkeypatch.setattr(daemon, "DAEMON_DIR", daemon_dir)
        monkeypatch.setattr(daemon, "SOCKET_PATH", daemon_dir / "daemon.sock")
        monkeypatch.setattr(daemon, "PID_FILE", daemon_dir / "daemon.pid")
        monkeypatch.setattr(daemon, "LOG_PATH", daemon_dir / "access.log")

        d = daemon.VaultDaemon(test_vault["path"], foreground=True)

        # Mock session store and audit logger
        from vault_cli.session import SessionStore
        from vault_cli.audit import AuditLogger

        d.session_store = SessionStore()
        d.audit_logger = AuditLogger(daemon_dir / "access.log")
        d.lock = threading.Lock()

        d._create_socket()

        assert (daemon_dir / "daemon.sock").exists()
        assert oct((daemon_dir / "daemon.sock").stat().st_mode)[-3:] == "600"

        d.socket.close()

    def test_create_socket_removes_stale(self, temp_vault_dir, test_vault, monkeypatch):
        """Test that stale socket is removed."""
        daemon_dir = temp_vault_dir / ".vault"
        daemon_dir.mkdir(parents=True, exist_ok=True)

        monkeypatch.setattr(daemon, "DAEMON_DIR", daemon_dir)
        monkeypatch.setattr(daemon, "SOCKET_PATH", daemon_dir / "daemon.sock")
        monkeypatch.setattr(daemon, "PID_FILE", daemon_dir / "daemon.pid")
        monkeypatch.setattr(daemon, "LOG_PATH", daemon_dir / "access.log")

        # Create stale socket
        (daemon_dir / "daemon.sock").write_text("")

        d = daemon.VaultDaemon(test_vault["path"], foreground=True)

        from vault_cli.session import SessionStore
        from vault_cli.audit import AuditLogger

        d.session_store = SessionStore()
        d.audit_logger = AuditLogger(daemon_dir / "access.log")
        d.lock = threading.Lock()

        d._create_socket()

        assert (daemon_dir / "daemon.sock").exists()
        d.socket.close()


class TestHandleConnection:
    """Tests for connection handling."""

    def test_handle_connection_ping(self, temp_vault_dir, test_vault, monkeypatch):
        """Test handling ping request."""
        daemon_dir = temp_vault_dir / ".vault"
        daemon_dir.mkdir(parents=True, exist_ok=True)

        monkeypatch.setattr(daemon, "DAEMON_DIR", daemon_dir)
        monkeypatch.setattr(daemon, "SOCKET_PATH", daemon_dir / "daemon.sock")
        monkeypatch.setattr(daemon, "PID_FILE", daemon_dir / "daemon.pid")
        monkeypatch.setattr(daemon, "LOG_PATH", daemon_dir / "access.log")

        d = daemon.VaultDaemon(test_vault["path"], foreground=True)

        from vault_cli.session import SessionStore
        from vault_cli.audit import AuditLogger

        d.session_store = SessionStore()
        d.audit_logger = AuditLogger(daemon_dir / "access.log")
        d.lock = threading.Lock()

        # Create mock connection
        mock_conn = Mock()
        mock_conn.recv.side_effect = [
            b'{"request_id": "ping-1", "action": "ping"}\n',
            b''
        ]

        d._handle_connection(mock_conn)

        # Check response was sent
        sent_data = mock_conn.sendall.call_args[0][0]
        response = json.loads(sent_data.decode().strip())

        assert response["status"] == "ok"
        assert response["data"]["version"] == "2.0.0"
        mock_conn.close.assert_called_once()

    def test_handle_connection_invalid_json(self, temp_vault_dir, test_vault, monkeypatch):
        """Test handling invalid JSON."""
        daemon_dir = temp_vault_dir / ".vault"
        daemon_dir.mkdir(parents=True, exist_ok=True)

        monkeypatch.setattr(daemon, "DAEMON_DIR", daemon_dir)
        monkeypatch.setattr(daemon, "LOG_PATH", daemon_dir / "access.log")

        d = daemon.VaultDaemon(test_vault["path"], foreground=True)

        from vault_cli.session import SessionStore
        from vault_cli.audit import AuditLogger

        d.session_store = SessionStore()
        d.audit_logger = AuditLogger(daemon_dir / "access.log")
        d.lock = threading.Lock()

        mock_conn = Mock()
        mock_conn.recv.side_effect = [b'not valid json\n', b'']

        d._handle_connection(mock_conn)

        sent_data = mock_conn.sendall.call_args[0][0]
        response = json.loads(sent_data.decode().strip())

        assert response["status"] == "error"
        mock_conn.close.assert_called_once()


class TestCleanupThread:
    """Tests for cleanup background thread."""

    def test_cleanup_sessions(self, temp_vault_dir, test_vault, monkeypatch, mock_time):
        """Test session cleanup."""
        daemon_dir = temp_vault_dir / ".vault"
        daemon_dir.mkdir(parents=True, exist_ok=True)

        monkeypatch.setattr(daemon, "DAEMON_DIR", daemon_dir)
        monkeypatch.setattr(daemon, "LOG_PATH", daemon_dir / "access.log")

        d = daemon.VaultDaemon(test_vault["path"], foreground=True)

        from vault_cli.session import SessionStore
        from vault_cli.audit import AuditLogger

        d.session_store = SessionStore()
        d.audit_logger = AuditLogger(daemon_dir / "access.log")
        d.lock = threading.Lock()

        # Create expired session
        session = d.session_store.create_session(
            root_pid=1000,
            derived_key=test_vault["key"],
            scope=["*"],
            ttl=10,
            command="test"
        )

        # Advance time
        mock_time[0] += 20

        # Run cleanup
        d._cleanup_sessions()

        assert d.session_store.get_session(session.session_id) is None


class TestSignalHandling:
    """Tests for signal handling."""

    def test_handle_shutdown(self, temp_vault_dir, test_vault):
        """Test shutdown signal handler."""
        d = daemon.VaultDaemon(test_vault["path"], foreground=True)
        d.running = True

        d._handle_shutdown(signal.SIGTERM, None)

        assert d.running is False

    def test_shutdown_logs_session_closure(self, temp_vault_dir, test_vault, monkeypatch):
        """Test that shutdown logs session closures (daemon logs but doesn't revoke)."""
        daemon_dir = temp_vault_dir / ".vault"
        daemon_dir.mkdir(parents=True, exist_ok=True)

        monkeypatch.setattr(daemon, "DAEMON_DIR", daemon_dir)
        monkeypatch.setattr(daemon, "SOCKET_PATH", daemon_dir / "daemon.sock")
        monkeypatch.setattr(daemon, "PID_FILE", daemon_dir / "daemon.pid")
        monkeypatch.setattr(daemon, "LOG_PATH", daemon_dir / "access.log")

        d = daemon.VaultDaemon(test_vault["path"], foreground=True)

        from vault_cli.session import SessionStore
        from vault_cli.audit import AuditLogger

        d.session_store = SessionStore()
        d.audit_logger = AuditLogger(daemon_dir / "access.log")
        d.lock = threading.Lock()

        # Create session
        session = d.session_store.create_session(
            root_pid=1000,
            derived_key=test_vault["key"],
            scope=["*"],
            ttl=3600,
            command="test"
        )

        d._create_socket()
        d._shutdown()

        # Verify socket and pid files cleaned up
        assert not (daemon_dir / "daemon.sock").exists()
        assert not (daemon_dir / "daemon.pid").exists()
