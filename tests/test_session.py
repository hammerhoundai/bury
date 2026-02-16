"""Unit tests for session store module."""

import time
from datetime import datetime, timezone, timedelta

import pytest

from vault_cli.session import Session, SessionStore, generate_session_id


class TestSession:
    """Tests for Session dataclass."""
    
    def test_session_creation(self):
        """Test creating a basic session."""
        now = datetime.now(timezone.utc)
        session = Session(
            session_id="vs-test123",
            root_pid=1000,
            pid_tree={1000, 1001},
            derived_key=b"x" * 32,
            scope=["work/*"],
            created_at=now,
            expires_at=now + timedelta(hours=1),
            last_accessed=now,
            access_count_allowed=0,
            access_count_denied=0,
            command="claude"
        )
        
        assert session.session_id == "vs-test123"
        assert session.root_pid == 1000
        assert session.command == "claude"
    
    def test_session_id_prefix_added(self):
        """Test that session ID gets vs- prefix if missing."""
        session = Session(
            session_id="test123",
            root_pid=1000,
            pid_tree={1000},
            derived_key=b"x" * 32,
            scope=["*"],
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc),
            last_accessed=datetime.now(timezone.utc),
            access_count_allowed=0,
            access_count_denied=0,
            command="test"
        )
        
        assert session.session_id.startswith("vs-")


class TestSessionStore:
    """Tests for SessionStore class."""
    
    def test_create_session(self, clean_session_store, mock_pid_tree):
        """Test basic session creation."""
        key = b"x" * 32
        
        session = clean_session_store.create_session(
            root_pid=1000,
            derived_key=key,
            scope=["work/*"],
            ttl=3600,
            command="claude"
        )
        
        assert session.session_id.startswith("vs-")
        assert session.root_pid == 1000
        assert session.scope == ["work/*"]
        assert session.derived_key == key
        assert session.command == "claude"
    
    def test_create_session_unique_ids(self, clean_session_store):
        """Test that session IDs are unique."""
        key = b"x" * 32
        ids = set()
        
        for i in range(10):
            session = clean_session_store.create_session(
                root_pid=1000 + i,
                derived_key=key,
                scope=["*"],
                ttl=3600,
                command="test"
            )
            assert session.session_id not in ids
            ids.add(session.session_id)
        
        assert len(ids) == 10
    
    def test_create_session_max_reached(self, clean_session_store):
        """Test that max sessions limit is enforced."""
        key = b"x" * 32
        
        # Create max sessions
        for i in range(SessionStore.MAX_SESSIONS):
            clean_session_store.create_session(
                root_pid=1000 + i,
                derived_key=key,
                scope=["*"],
                ttl=3600,
                command="test"
            )
        
        # Next session should fail
        with pytest.raises(ValueError, match="Maximum sessions"):
            clean_session_store.create_session(
                root_pid=2000,
                derived_key=key,
                scope=["*"],
                ttl=3600,
                command="test"
            )
    
    def test_get_session(self, clean_session_store, sample_session):
        """Test retrieving session by ID."""
        retrieved = clean_session_store.get_session(sample_session.session_id)
        
        assert retrieved is not None
        assert retrieved.session_id == sample_session.session_id
        assert retrieved.root_pid == sample_session.root_pid
    
    def test_get_session_not_found(self, clean_session_store):
        """Test retrieving non-existent session."""
        result = clean_session_store.get_session("vs-nonexistent")
        
        assert result is None
    
    def test_get_session_by_pid(self, clean_session_store, sample_session):
        """Test retrieving session by PID."""
        # PID 1000 is in the mock tree for sample_session
        retrieved = clean_session_store.get_session_by_pid(1000)
        
        assert retrieved is not None
        assert retrieved.session_id == sample_session.session_id
    
    def test_get_session_by_pid_not_found(self, clean_session_store):
        """Test retrieving session by non-indexed PID."""
        result = clean_session_store.get_session_by_pid(99999)
        
        assert result is None
    
    def test_destroy_session(self, clean_session_store, sample_session):
        """Test destroying a session."""
        session_id = sample_session.session_id
        
        result = clean_session_store.destroy_session(session_id)
        
        assert result is True
        assert clean_session_store.get_session(session_id) is None
    
    def test_destroy_session_not_found(self, clean_session_store):
        """Test destroying non-existent session."""
        result = clean_session_store.destroy_session("vs-nonexistent")
        
        assert result is False
    
    def test_destroy_session_cleans_pid_index(self, clean_session_store, sample_session):
        """Test that destroying session removes PID index entries."""
        session_id = sample_session.session_id
        
        clean_session_store.destroy_session(session_id)
        
        # PIDs should no longer be in index
        for pid in sample_session.pid_tree:
            assert clean_session_store.get_session_by_pid(pid) is None
    
    def test_list_sessions(self, clean_session_store):
        """Test listing all sessions."""
        key = b"x" * 32
        
        # Create multiple sessions
        for i in range(3):
            clean_session_store.create_session(
                root_pid=1000 + i,
                derived_key=key,
                scope=["*"],
                ttl=3600,
                command="test"
            )
        
        sessions = clean_session_store.list_sessions()
        
        assert len(sessions) == 3
    
    def test_list_sessions_empty(self, clean_session_store):
        """Test listing sessions when none exist."""
        sessions = clean_session_store.list_sessions()
        
        assert sessions == []


class TestValidateAccess:
    """Tests for access validation."""
    
    def test_validate_access_allowed(self, clean_session_store, sample_session):
        """Test access allowed within scope and PID tree."""
        allowed, session, reason = clean_session_store.validate_access(
            sample_session.session_id,
            client_pid=1000,
            path="work/api/key"
        )
        
        assert allowed is True
        assert session is not None
        assert reason == "allowed"
    
    def test_validate_access_out_of_scope(self, clean_session_store, sample_session):
        """Test access denied outside scope."""
        allowed, session, reason = clean_session_store.validate_access(
            sample_session.session_id,
            client_pid=1000,
            path="personal/bank"
        )
        
        assert allowed is False
        assert session is not None  # Session object returned for logging
        assert reason == "out-of-scope"
        assert session.access_count_denied == 1
    
    def test_validate_access_wrong_pid(self, clean_session_store, sample_session):
        """Test access denied from wrong PID."""
        allowed, session, reason = clean_session_store.validate_access(
            sample_session.session_id,
            client_pid=9999,  # Not in PID tree
            path="work/api/key"
        )
        
        assert allowed is False
        assert reason == "wrong-pid"
    
    def test_validate_access_expired(self, clean_session_store, mock_time):
        """Test access denied for expired session."""
        from vault_cli.session import SessionStore
        store = SessionStore()
        
        # Create session with short TTL
        key = b"x" * 32
        session = store.create_session(
            root_pid=1000,
            derived_key=key,
            scope=["*"],
            ttl=10,  # 10 seconds
            command="test"
        )
        
        # Advance time past expiration
        mock_time[0] += 20
        
        allowed, _, reason = store.validate_access(
            session.session_id,
            client_pid=1000,
            path="work/api/key"
        )
        
        assert allowed is False
        assert reason == "expired"
    
    def test_validate_access_no_session(self, clean_session_store):
        """Test access denied for non-existent session."""
        allowed, session, reason = clean_session_store.validate_access(
            "vs-nonexistent",
            client_pid=1000,
            path="work/api/key"
        )
        
        assert allowed is False
        assert session is None
        assert reason == "no-session"
    
    def test_validate_access_increments_counters(self, clean_session_store, sample_session):
        """Test that access counters are incremented."""
        # Allowed access
        clean_session_store.validate_access(
            sample_session.session_id,
            client_pid=1000,
            path="work/api/key"
        )
        
        # Denied access
        clean_session_store.validate_access(
            sample_session.session_id,
            client_pid=1000,
            path="personal/bank"
        )
        
        session = clean_session_store.get_session(sample_session.session_id)
        assert session.access_count_allowed == 1
        assert session.access_count_denied == 1


class TestCleanup:
    """Tests for session cleanup."""
    
    def test_cleanup_expired(self, clean_session_store, mock_time):
        """Test cleanup of expired sessions."""
        key = b"x" * 32
        
        # Create session with short TTL
        session = clean_session_store.create_session(
            root_pid=1000,
            derived_key=key,
            scope=["*"],
            ttl=10,
            command="test"
        )
        
        # Advance time past expiration
        mock_time[0] += 20
        
        removed = clean_session_store.cleanup_expired()
        
        assert len(removed) == 1
        assert removed[0] == session.session_id
        assert clean_session_store.get_session(session.session_id) is None
    
    def test_cleanup_expired_none_expired(self, clean_session_store, mock_time):
        """Test cleanup when no sessions expired."""
        key = b"x" * 32
        
        # Create session with long TTL
        session = clean_session_store.create_session(
            root_pid=1000,
            derived_key=key,
            scope=["*"],
            ttl=3600,
            command="test"
        )
        
        # Don't advance time
        removed = clean_session_store.cleanup_expired()
        
        assert len(removed) == 0
        assert clean_session_store.get_session(session.session_id) is not None
    
    def test_cleanup_dead_pids(self, clean_session_store, mock_pid_tree):
        """Test cleanup of sessions with dead PIDs."""
        key = b"x" * 32
        
        # Create session with PID that will die
        session = clean_session_store.create_session(
            root_pid=1,  # PID 1 is not in mock_alive set
            derived_key=key,
            scope=["*"],
            ttl=3600,
            command="test"
        )
        
        removed = clean_session_store.cleanup_dead_pids()
        
        assert len(removed) == 1
        assert removed[0][0] == session.session_id
        assert removed[0][1] == 1
    
    def test_revoke_all(self, clean_session_store):
        """Test revoking all sessions."""
        key = b"x" * 32
        
        # Create multiple sessions
        for i in range(5):
            clean_session_store.create_session(
                root_pid=1000 + i,
                derived_key=key,
                scope=["*"],
                ttl=3600,
                command="test"
            )
        
        count = clean_session_store.revoke_all()
        
        assert count == 5
        assert len(clean_session_store.list_sessions()) == 0
        assert len(clean_session_store.pid_index) == 0


class TestGenerateSessionId:
    """Tests for session ID generation."""
    
    def test_generate_session_id_format(self):
        """Test that generated IDs have correct format."""
        session_id = generate_session_id()
        
        assert session_id.startswith("vs-")
        # vs- + 8 characters = 11 total
        assert len(session_id) == 11
        # After prefix should be alphanumeric
        suffix = session_id[3:]
        assert suffix.isalnum()
