#!/usr/bin/env python3
"""Session Store - In-memory session management for PID-bound vault access.

Provides secure session storage with fast PID lookups, TTL expiration,
and automatic cleanup of dead processes.
"""

import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

from .pid_tree import get_pid_tree, is_pid_alive, is_pid_related_to_session


@dataclass
class Session:
    """An active vault session bound to a process tree."""

    session_id: str              # Format: "vs-{8-char-alphanumeric}"
    root_pid: int                # PID that created the session
    pid_tree: Set[int]           # All PIDs in the process tree
    derived_key: bytes           # 32-byte key from Argon2id
    scope: List[str]             # Allowed path patterns
    created_at: datetime         # Session creation time
    expires_at: datetime         # TTL expiration time
    last_accessed: datetime      # Last activity time
    access_count_allowed: int    # Successful accesses
    access_count_denied: int     # Denied accesses
    command: str                 # Command that was launched
    root_pid_start_time: Optional[float] = None  # Start time to detect PID reuse
    last_pid_refresh: float = 0  # Timestamp of last PID tree refresh

    def __post_init__(self):
        """Initialize computed fields."""
        if not self.session_id.startswith("vs-"):
            self.session_id = f"vs-{self.session_id}"


class SessionStore:
    """In-memory storage for active sessions."""

    MAX_SESSIONS = 32
    PID_REFRESH_INTERVAL = 5.0  # seconds

    def __init__(self):
        self.sessions: Dict[str, Session] = {}
        self.pid_index: Dict[int, str] = {}  # pid -> session_id
        self.lock = threading.Lock()

    def create_session(
        self,
        root_pid: int,
        derived_key: bytes,
        scope: List[str],
        ttl: int,
        command: str
    ) -> Session:
        """Create a new session.

        Args:
            root_pid: PID that created the session
            derived_key: 32-byte derived encryption key
            scope: List of allowed path patterns
            ttl: Time-to-live in seconds
            command: Command that was launched

        Returns:
            The created Session object

        Raises:
            ValueError: If max sessions reached

        """
        with self.lock:
            if len(self.sessions) >= self.MAX_SESSIONS:
                raise ValueError(f"Maximum sessions ({self.MAX_SESSIONS}) reached")

            # Generate unique session ID
            session_id = f"vs-{uuid.uuid4().hex[:8]}"

            # Ensure uniqueness
            while session_id in self.sessions:
                session_id = f"vs-{uuid.uuid4().hex[:8]}"

            now = datetime.now(timezone.utc)

            # Get initial PID tree
            pid_tree = get_pid_tree(root_pid)

            # Get process start time for PID reuse detection
            from .pid_tree import get_process_start_time
            start_time = get_process_start_time(root_pid)

            session = Session(
                session_id=session_id,
                root_pid=root_pid,
                pid_tree=pid_tree,
                derived_key=derived_key,
                scope=scope,
                created_at=now,
                expires_at=datetime.fromtimestamp(
                    now.timestamp() + ttl, tz=timezone.utc
                ),
                last_accessed=now,
                access_count_allowed=0,
                access_count_denied=0,
                command=command,
                root_pid_start_time=start_time,
                last_pid_refresh=now.timestamp()
            )

            self.sessions[session_id] = session

            # Update PID index
            for pid in pid_tree:
                self.pid_index[pid] = session_id

            return session

    def get_session(self, session_id: str) -> Optional[Session]:
        """Get a session by ID.

        Args:
            session_id: The session ID

        Returns:
            Session object or None if not found

        """
        with self.lock:
            return self.sessions.get(session_id)

    def get_session_by_pid(self, pid: int) -> Optional[Session]:
        """Get a session by PID (must be in session's PID tree).

        Args:
            pid: Process ID

        Returns:
            Session object or None if not found

        """
        with self.lock:
            session_id = self.pid_index.get(pid)
            if session_id:
                return self.sessions.get(session_id)
            return None

    def destroy_session(self, session_id: str) -> bool:
        """Destroy a session.

        Args:
            session_id: The session ID

        Returns:
            True if session was destroyed, False if not found

        """
        with self.lock:
            session = self.sessions.pop(session_id, None)
            if session:
                # Remove from PID index
                for pid in session.pid_tree:
                    self.pid_index.pop(pid, None)
                return True
            return False

    def list_sessions(self) -> List[Session]:
        """List all active sessions.

        Returns:
            List of Session objects

        """
        with self.lock:
            return list(self.sessions.values())

    def validate_access(
        self,
        session_id: str,
        client_pid: int,
        path: str
    ) -> Tuple[bool, Optional[Session], str]:
        """Validate if a client can access a path.

        Args:
            session_id: The session ID
            client_pid: The requesting process ID
            path: The vault path being accessed

        Returns:
            Tuple of (allowed, session_or_none, reason)

        """
        import fnmatch
        import time

        with self.lock:
            session = self.sessions.get(session_id)
            if not session:
                return False, None, "no-session"

            now = datetime.now(timezone.utc)

            # Check expiration
            if now > session.expires_at:
                return False, session, "expired"

            # Refresh PID tree if needed
            if time.time() - session.last_pid_refresh > self.PID_REFRESH_INTERVAL:
                session.pid_tree = get_pid_tree(session.root_pid)
                session.last_pid_refresh = time.time()

                # Update PID index
                for pid in session.pid_tree:
                    if pid not in self.pid_index:
                        self.pid_index[pid] = session_id

            # Check PID membership - use ancestry check for wrapper support
            # This handles cases like `uv run` which spawn processes in new process groups
            if not is_pid_related_to_session(client_pid, session.root_pid):
                return False, session, "wrong-pid"

            # Check scope
            allowed = False
            for pattern in session.scope:
                if fnmatch.fnmatch(path, pattern):
                    allowed = True
                    break

            if not allowed:
                session.access_count_denied += 1
                session.last_accessed = now
                return False, session, "out-of-scope"

            # Access allowed
            session.access_count_allowed += 1
            session.last_accessed = now
            return True, session, "allowed"

    def cleanup_expired(self) -> List[str]:
        """Remove expired sessions.

        Returns:
            List of removed session IDs

        """
        now = datetime.now(timezone.utc)
        removed = []

        with self.lock:
            expired_ids = [
                sid for sid, session in self.sessions.items()
                if now > session.expires_at
            ]

            for sid in expired_ids:
                session = self.sessions.pop(sid, None)
                if session:
                    for pid in session.pid_tree:
                        self.pid_index.pop(pid, None)
                    removed.append(sid)

        return removed

    def cleanup_dead_pids(self) -> List[Tuple[str, int]]:
        """Remove sessions whose root PID is dead.

        Returns:
            List of (session_id, root_pid) tuples for removed sessions

        """
        removed = []

        with self.lock:
            dead_ids = []

            for sid, session in self.sessions.items():
                if not is_pid_alive(session.root_pid):
                    dead_ids.append(sid)
                else:
                    # Also check for PID reuse
                    from .pid_tree import get_process_start_time
                    current_start = get_process_start_time(session.root_pid)
                    if (session.root_pid_start_time is not None and
                        current_start is not None and
                        abs(current_start - session.root_pid_start_time) > 1.0):
                        # PID was reused by different process
                        dead_ids.append(sid)

            for sid in dead_ids:
                session = self.sessions.pop(sid, None)
                if session:
                    for pid in session.pid_tree:
                        self.pid_index.pop(pid, None)
                    removed.append((sid, session.root_pid))

        return removed

    def revoke_all(self) -> int:
        """Revoke all sessions.

        Returns:
            Number of sessions revoked

        """
        with self.lock:
            count = len(self.sessions)
            self.sessions.clear()
            self.pid_index.clear()
            return count


def generate_session_id() -> str:
    """Generate a unique session ID."""
    return f"vs-{uuid.uuid4().hex[:8]}"
