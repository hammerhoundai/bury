"""Pytest fixtures and utilities for vault-cli tests."""

import os
import json
import socket
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
import nacl.pwhash
import nacl.secret
import nacl.utils

# Add src to path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from vault_cli.main import derive_key, encrypt_secret, init_db, get_metadata


@pytest.fixture
def temp_vault_dir():
    """Create a temporary directory for vault files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def test_vault(temp_vault_dir):
    """Create an initialized vault with test data."""
    vault_path = temp_vault_dir / "test.vault"
    password = "test_password_123"
    
    # Initialize vault
    init_db(vault_path)
    
    # Create metadata
    salt = nacl.utils.random(16)
    key = derive_key(password, salt)
    canary_ciphertext, canary_nonce = encrypt_secret(key, "VAULT_CANARY")
    
    import sqlite3
    conn = sqlite3.connect(vault_path)
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO metadata (id, salt, opslimit, memlimit, canary_ciphertext, canary_nonce)
           VALUES (1, ?, ?, ?, ?, ?)""",
        (salt, nacl.pwhash.OPSLIMIT_INTERACTIVE, 
         nacl.pwhash.MEMLIMIT_INTERACTIVE, canary_ciphertext, canary_nonce)
    )
    
    # Add test entries
    entries = [
        ("work/api/key", "sk_live_work_123"),
        ("work/db/password", "db_pass_456"),
        ("personal/email/password", "email_pass_789"),
        ("test/secret", "test_secret_abc"),
    ]
    
    for path, secret in entries:
        data = json.dumps({"secret": secret, "note": ""})
        ciphertext, nonce = encrypt_secret(key, data)
        now = datetime.now(timezone.utc).isoformat()
        cursor.execute(
            """INSERT INTO entries (path, ciphertext, nonce, created, modified)
               VALUES (?, ?, ?, ?, ?)""",
            (path, ciphertext, nonce, now, now)
        )
    
    conn.commit()
    conn.close()
    
    return {
        "path": vault_path,
        "password": password,
        "key": key,
        "entries": {e[0]: e[1] for e in entries}
    }


@pytest.fixture
def mock_daemon_dir(temp_vault_dir, monkeypatch):
    """Mock daemon directory to use temp location."""
    daemon_dir = temp_vault_dir / ".vault"
    daemon_dir.mkdir(parents=True, exist_ok=True)
    
    # Patch all daemon path references
    from vault_cli import daemon, audit
    monkeypatch.setattr(daemon, "DAEMON_DIR", daemon_dir)
    monkeypatch.setattr(daemon, "SOCKET_PATH", daemon_dir / "daemon.sock")
    monkeypatch.setattr(daemon, "PID_FILE", daemon_dir / "daemon.pid")
    monkeypatch.setattr(daemon, "LOG_PATH", daemon_dir / "access.log")
    
    yield daemon_dir


@pytest.fixture
def mock_pid_tree(monkeypatch):
    """Mock PID tree functions for predictable testing."""
    from vault_cli import pid_tree
    
    # Mock data: PID -> tree mapping
    mock_trees = {
        1000: {1000, 1001, 1002},  # Root with children
        2000: {2000},  # Single process
        3000: {3000, 3001, 3002, 3003},  # Root with multiple children
    }
    
    def mock_get_pid_tree(pid, use_cache=True):
        return mock_trees.get(pid, {pid})
    
    def mock_is_pid_alive(pid):
        return pid in mock_trees or pid > 5000  # PIDs > 5000 considered alive
    
    def mock_get_process_command(pid):
        commands = {
            1000: "claude",
            2000: "python",
            3000: "bash",
            1001: "node",
            1002: "git",
        }
        return commands.get(pid, "unknown")
    
    def mock_get_process_start_time(pid):
        # Return consistent start times for PID reuse detection
        return float(pid * 1000)  # Unique start time per PID

    def mock_get_process_ancestry(pid):
        # Mock ancestry: each PID has parent pid-1 (simplified model)
        ancestors = set()
        current = pid
        for _ in range(10):  # Max depth
            parent = current - 1 if current > 1 else 0
            if parent <= 0:
                break
            ancestors.add(parent)
            current = parent
        return ancestors

    def mock_is_pid_related_to_session(client_pid, session_root_pid):
        # Check if client is in session tree OR session root is in client ancestry
        tree = mock_get_pid_tree(session_root_pid)
        if client_pid in tree:
            return True
        ancestry = mock_get_process_ancestry(client_pid)
        if session_root_pid in ancestry:
            return True
        return False

    monkeypatch.setattr(pid_tree, "get_pid_tree", mock_get_pid_tree)
    monkeypatch.setattr(pid_tree, "is_pid_alive", mock_is_pid_alive)
    monkeypatch.setattr(pid_tree, "get_process_command", mock_get_process_command)
    monkeypatch.setattr(pid_tree, "get_process_start_time", mock_get_process_start_time)
    monkeypatch.setattr(pid_tree, "get_process_ancestry", mock_get_process_ancestry)
    monkeypatch.setattr(pid_tree, "is_pid_related_to_session", mock_is_pid_related_to_session)

    yield mock_trees


@pytest.fixture
def clean_session_store():
    """Create a fresh session store for each test."""
    from vault_cli.session import SessionStore
    store = SessionStore()
    yield store
    # Cleanup: revoke all sessions
    store.revoke_all()


@pytest.fixture
def audit_logger(temp_vault_dir):
    """Create an audit logger with temp log path."""
    from vault_cli.audit import AuditLogger
    log_path = temp_vault_dir / "access.log"
    logger = AuditLogger(log_path)
    yield logger


@pytest.fixture
def running_daemon(temp_vault_dir, test_vault, monkeypatch):
    """Start a daemon process for integration tests."""
    from vault_cli.daemon import VaultDaemon
    
    daemon_dir = temp_vault_dir / ".vault"
    daemon_dir.mkdir(parents=True, exist_ok=True)
    
    # Patch paths
    from vault_cli import daemon
    monkeypatch.setattr(daemon, "DAEMON_DIR", daemon_dir)
    monkeypatch.setattr(daemon, "SOCKET_PATH", daemon_dir / "daemon.sock")
    monkeypatch.setattr(daemon, "PID_FILE", daemon_dir / "daemon.pid")
    monkeypatch.setattr(daemon, "LOG_PATH", daemon_dir / "access.log")
    
    # Start daemon in foreground mode with threading
    vault_daemon = VaultDaemon(test_vault["path"], foreground=True)
    
    # Create socket only, don't fork
    daemon_dir.mkdir(parents=True, exist_ok=True)
    
    from vault_cli.session import SessionStore
    from vault_cli.audit import AuditLogger
    
    vault_daemon.session_store = SessionStore()
    vault_daemon.audit_logger = AuditLogger(daemon_dir / "access.log")
    vault_daemon.lock = threading.Lock()
    
    # Create socket
    import socket as sock
    if daemon.SOCKET_PATH.exists():
        daemon.SOCKET_PATH.unlink()
    vault_daemon.socket = sock.socket(sock.AF_UNIX, sock.SOCK_STREAM)
    vault_daemon.socket.bind(str(daemon.SOCKET_PATH))
    daemon.SOCKET_PATH.chmod(0o600)
    vault_daemon.socket.listen(32)
    vault_daemon.socket.settimeout(1.0)
    
    vault_daemon.running = True
    
    # Start in background thread
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
    
    # Wait for daemon to be ready
    time.sleep(0.1)
    
    yield vault_daemon
    
    # Cleanup
    vault_daemon.running = False
    if vault_daemon.socket:
        vault_daemon.socket.close()
    if daemon.SOCKET_PATH.exists():
        daemon.SOCKET_PATH.unlink()


@pytest.fixture
def sample_session(clean_session_store, test_vault, mock_pid_tree):
    """Create a sample session for testing."""
    session = clean_session_store.create_session(
        root_pid=1000,
        derived_key=test_vault["key"],
        scope=["work/*", "test/*"],
        ttl=3600,
        command="claude"
    )
    return session


@pytest.fixture
def mock_time(monkeypatch):
    """Mock time functions for predictable TTL testing."""
    current_time = [time.time()]
    
    def mock_time_func():
        return current_time[0]
    
    def mock_sleep(seconds):
        current_time[0] += seconds
    
    class MockDatetime:
        @classmethod
        def now(cls, tz=None):
            from datetime import datetime, timezone
            return datetime.fromtimestamp(current_time[0], tz=tz or timezone.utc)
        
        @classmethod
        def fromtimestamp(cls, ts, tz=None):
            from datetime import datetime
            return datetime.fromtimestamp(ts, tz=tz)
    
    monkeypatch.setattr(time, "time", mock_time_func)
    monkeypatch.setattr(time, "sleep", mock_sleep)
    
    # Patch datetime in session module
    from vault_cli import session
    monkeypatch.setattr(session, "datetime", MockDatetime)
    
    yield current_time


@pytest.fixture
def env_cleanup():
    """Clean up environment variables after test."""
    original_env = dict(os.environ)
    yield
    # Restore original environment
    for key in list(os.environ.keys()):
        if key not in original_env:
            del os.environ[key]
    os.environ.update(original_env)


@pytest.fixture
def mock_socket():
    """Create a mock socket for testing protocol."""
    mock = Mock()
    mock.recv.side_effect = [b'{"request_id": "test", "action": "ping"}\n', b'']
    return mock


def assert_log_entry(audit_logger, result, action, path=None):
    """Helper to verify a log entry exists."""
    recent = audit_logger.read_recent(100)
    for line in recent:
        parts = line.strip().split()
        if len(parts) >= 5:
            if parts[2] == result and parts[3] == action:
                if path is None or parts[4] == path:
                    return True
    return False
