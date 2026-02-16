#!/usr/bin/env python3
"""Vault Daemon - Background service for PID-bound session management.

Provides Unix socket communication for CLI clients, maintains sessions
in memory, and handles authentication via process tree verification.
"""

import json
import os
import signal
import socket
import sys
import threading
from pathlib import Path
from typing import Optional

# Daemon paths
DAEMON_DIR = Path.home() / ".vault"
SOCKET_PATH = DAEMON_DIR / "daemon.sock"
PID_FILE = DAEMON_DIR / "daemon.pid"
LOG_PATH = DAEMON_DIR / "access.log"

# Constants
MAX_CONNECTIONS = 32
SOCKET_TIMEOUT = 5.0
CLEANUP_INTERVAL = 30  # seconds


class VaultDaemon:
    """Background daemon managing vault sessions."""

    def __init__(self, vault_path: Path, foreground: bool = False):
        self.vault_path = vault_path
        self.foreground = foreground
        self.running = False
        self.socket: Optional[socket.socket] = None
        self.session_store = None  # Set after importing session module
        self.audit_logger = None  # Set after importing audit module
        self.cleanup_thread: Optional[threading.Thread] = None
        self.lock = threading.Lock()

    def start(self) -> bool:
        """Start the daemon."""
        # Clean up stale files before checking if running
        self._cleanup_stale_files()

        # Check if already running
        if self._is_running():
            print(f"Vault daemon already running (PID: {self._read_pid()})", file=sys.stderr)
            return False

        # Ensure daemon directory exists
        DAEMON_DIR.mkdir(parents=True, exist_ok=True)
        DAEMON_DIR.chmod(0o700)

        # Import modules here to avoid circular imports
        from .audit import AuditLogger
        from .session import SessionStore

        self.session_store = SessionStore()
        self.audit_logger = AuditLogger(LOG_PATH)

        if self.foreground:
            self._run_foreground()
        else:
            self._fork_and_run()

        return True

    def stop(self) -> bool:
        """Stop the daemon."""
        pid = self._read_pid()
        if not pid:
            print("Vault daemon is not running", file=sys.stderr)
            return False

        try:
            os.kill(pid, signal.SIGTERM)
            print(f"Vault daemon stopped (PID: {pid})")
            return True
        except ProcessLookupError:
            # Process not found, clean up stale files
            self._cleanup_files()
            print("Vault daemon was not running (cleaned up stale files)")
            return True

    def _is_running(self) -> bool:
        """Check if daemon is already running."""
        pid = self._read_pid()
        if not pid:
            return False

        try:
            os.kill(pid, 0)  # Check if process exists
            return True
        except ProcessLookupError:
            # Stale PID file, clean it up
            self._cleanup_files()
            return False

    def _read_pid(self) -> Optional[int]:
        """Read PID from PID file."""
        if not PID_FILE.exists():
            return None

        try:
            return int(PID_FILE.read_text().strip())
        except (ValueError, OSError):
            return None

    def _write_pid(self) -> None:
        """Write current PID to PID file."""
        PID_FILE.write_text(str(os.getpid()))
        PID_FILE.chmod(0o600)

    def _cleanup_stale_files(self) -> None:
        """Detect and clean up stale socket and PID files from crashed daemon."""
        # Check for stale socket file
        if SOCKET_PATH.exists():
            # Try to connect - if fails, socket is stale
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                sock.connect(str(SOCKET_PATH))
                sock.close()
                # If we get here, socket is active (daemon is running)
            except (socket.error, ConnectionRefusedError, OSError):
                # Socket is stale, remove it
                try:
                    SOCKET_PATH.unlink()
                    print(f"[INFO] Removed stale socket file: {SOCKET_PATH}")
                except OSError:
                    pass

        # Check for stale PID file
        if PID_FILE.exists():
            pid = self._read_pid()
            if pid:
                try:
                    os.kill(pid, 0)  # Check if process exists
                    # Process exists - PID file is valid
                except ProcessLookupError:
                    # Process doesn't exist - stale PID file
                    try:
                        PID_FILE.unlink()
                        print(f"[INFO] Removed stale PID file: {PID_FILE}")
                    except OSError:
                        pass
            else:
                # Invalid PID in file
                try:
                    PID_FILE.unlink()
                    print(f"[INFO] Removed invalid PID file: {PID_FILE}")
                except OSError:
                    pass

    def _cleanup_files(self) -> None:
        """Remove socket and PID files."""
        if SOCKET_PATH.exists():
            SOCKET_PATH.unlink()
        if PID_FILE.exists():
            PID_FILE.unlink()

    def _fork_and_run(self) -> None:
        """Fork to background and run daemon."""
        # First fork
        pid = os.fork()
        if pid > 0:
            # Parent process
            print(f"Vault daemon started (PID: {pid})")
            sys.exit(0)

        # Decouple from parent environment
        os.chdir("/")
        os.setsid()
        os.umask(0)

        # Second fork
        pid = os.fork()
        if pid > 0:
            sys.exit(0)

        # Redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()

        with open("/dev/null") as devnull:
            os.dup2(devnull.fileno(), sys.stdin.fileno())

        # Redirect stdout/stderr to log file if it exists
        log_out = open(DAEMON_DIR / "daemon.log", "a")
        os.dup2(log_out.fileno(), sys.stdout.fileno())
        os.dup2(log_out.fileno(), sys.stderr.fileno())

        # Run daemon
        self._run()

    def _run_foreground(self) -> None:
        """Run daemon in foreground."""
        print(f"[INFO] Vault daemon starting (PID: {os.getpid()})")
        self._run()

    def _run(self) -> None:
        """Main daemon loop."""
        # Write PID file
        self._write_pid()

        # Setup signal handlers
        signal.signal(signal.SIGTERM, self._handle_shutdown)
        signal.signal(signal.SIGINT, self._handle_shutdown)

        # Create Unix socket
        self._create_socket()

        self.running = True

        # Start cleanup thread
        self._start_cleanup_thread()

        # Log daemon start
        self.audit_logger.log_access(
            pid=os.getpid(),
            command="vault-daemon",
            result="STARTED",
            action="DAEMON",
            path="-"
        )

        try:
            self._main_loop()
        finally:
            self._shutdown()

    def _create_socket(self) -> None:
        """Create Unix domain socket."""
        # Remove stale socket if exists
        if SOCKET_PATH.exists():
            SOCKET_PATH.unlink()

        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.bind(str(SOCKET_PATH))
        SOCKET_PATH.chmod(0o600)
        self.socket.listen(MAX_CONNECTIONS)
        self.socket.settimeout(SOCKET_TIMEOUT)

        if self.foreground:
            print(f"[INFO] Listening on {SOCKET_PATH}")

    def _main_loop(self) -> None:
        """Main event loop accepting connections."""
        while self.running:
            try:
                conn, _ = self.socket.accept()
                # Handle each connection in a thread
                thread = threading.Thread(target=self._handle_connection, args=(conn,))
                thread.daemon = True
                thread.start()
            except socket.timeout:
                continue
            except OSError:
                if self.running:
                    raise
                break

    def _handle_connection(self, conn: socket.socket) -> None:
        """Handle a single client connection."""
        try:
            conn.settimeout(SOCKET_TIMEOUT)
            data = b""

            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\n" in data:
                    break

            if data:
                response = self._process_request(data.decode("utf-8").strip())
                conn.sendall((response + "\n").encode("utf-8"))
        except Exception as e:
            error_response = json.dumps({
                "status": "error",
                "error": {"code": "DAEMON_ERROR", "message": str(e)}
            })
            conn.sendall((error_response + "\n").encode("utf-8"))
        finally:
            conn.close()

    def _process_request(self, request_str: str) -> str:
        """Process a JSON request and return JSON response."""
        from .protocol import handle_request, parse_request, serialize_response

        try:
            request = parse_request(request_str)
            response = handle_request(
                request,
                self.session_store,
                self.audit_logger,
                self.vault_path,
                self.lock
            )
            return serialize_response(response)
        except Exception as e:
            return json.dumps({
                "request_id": getattr(request, 'request_id', 'unknown') if 'request' in dir() else 'unknown',
                "status": "error",
                "error": {"code": "INVALID_REQUEST", "message": str(e)}
            })

    def _start_cleanup_thread(self) -> None:
        """Start background cleanup thread."""
        def cleanup_loop():
            while self.running:
                import time
                time.sleep(CLEANUP_INTERVAL)
                if self.running:
                    self._cleanup_sessions()

        self.cleanup_thread = threading.Thread(target=cleanup_loop)
        self.cleanup_thread.daemon = True
        self.cleanup_thread.start()

    def _cleanup_sessions(self) -> None:
        """Clean up expired and dead sessions."""
        with self.lock:
            expired = self.session_store.cleanup_expired()
            dead = self.session_store.cleanup_dead_pids()

            for session_id in expired:
                self.audit_logger.log_access(
                    pid=0,
                    command="cleanup",
                    result="EXPIRED",
                    action="SESSION",
                    path=session_id,
                    reason="ttl-expired"
                )

            for session_id, pid in dead:
                self.audit_logger.log_access(
                    pid=pid,
                    command="cleanup",
                    result="REVOKED",
                    action="SESSION",
                    path=session_id,
                    reason="pid-dead"
                )

    def _handle_shutdown(self, signum: int, frame) -> None:
        """Handle shutdown signals."""
        self.running = False

    def _shutdown(self) -> None:
        """Clean shutdown."""
        if self.foreground:
            print("\n[INFO] Shutting down daemon...")

        # Destroy all sessions
        if self.session_store:
            sessions = self.session_store.list_sessions()
            for session in sessions:
                self.audit_logger.log_access(
                    pid=session.root_pid,
                    command=session.command,
                    result="REVOKED",
                    action="SESSION",
                    path=session.session_id,
                    reason="daemon-shutdown"
                )

        # Close socket
        if self.socket:
            self.socket.close()

        # Clean up files
        self._cleanup_files()

        if self.foreground:
            print("[INFO] Daemon stopped")


def ping_daemon() -> bool:
    """Check if daemon is running and responsive."""
    if not SOCKET_PATH.exists():
        return False

    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect(str(SOCKET_PATH))

        request = json.dumps({"request_id": "ping", "action": "ping"})
        sock.sendall((request + "\n").encode("utf-8"))

        response = sock.recv(1024).decode("utf-8").strip()
        sock.close()

        data = json.loads(response)
        return data.get("status") == "ok"
    except Exception:
        return False


def send_request(request: dict) -> dict:
    """Send a request to the daemon and return the response."""
    if not SOCKET_PATH.exists():
        return {
            "status": "error",
            "error": {"code": "DAEMON_NOT_RUNNING", "message": "Vault daemon not running. Start with: vault daemon"}
        }

    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(10.0)
        sock.connect(str(SOCKET_PATH))

        request_str = json.dumps(request)
        sock.sendall((request_str + "\n").encode("utf-8"))

        response_data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response_data += chunk
            if b"\n" in response_data:
                break

        sock.close()
        return json.loads(response_data.decode("utf-8").strip())
    except socket.timeout:
        return {
            "status": "error",
            "error": {"code": "TIMEOUT", "message": "Daemon request timed out"}
        }
    except Exception as e:
        return {
            "status": "error",
            "error": {"code": "CONNECTION_ERROR", "message": str(e)}
        }
