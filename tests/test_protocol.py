"""Unit tests for Unix socket protocol module."""

import json
import sqlite3
from datetime import datetime, timezone
from unittest.mock import Mock, patch

import pytest

from vault_cli.protocol import (
    Request,
    Response,
    parse_request,
    serialize_response,
    error_response,
    ok_response,
    handle_request,
    handle_ping,
    handle_create_session,
    handle_get,
    handle_destroy_session,
    handle_list_sessions,
    ERROR_CODES,
)


class TestRequestResponse:
    """Tests for Request and Response dataclasses."""

    def test_request_creation(self):
        """Test creating a Request."""
        req = Request(
            request_id="req-123",
            action="ping",
            session_id=None,
            payload={}
        )

        assert req.request_id == "req-123"
        assert req.action == "ping"

    def test_response_creation(self):
        """Test creating a Response."""
        resp = Response(
            request_id="req-123",
            status="ok",
            data={"version": "2.0.0"},
            error=None
        )

        assert resp.request_id == "req-123"
        assert resp.status == "ok"


class TestParseRequest:
    """Tests for request parsing."""

    def test_parse_request_valid(self):
        """Test parsing valid JSON request."""
        data = json.dumps({
            "request_id": "req-123",
            "action": "ping"
        })

        req = parse_request(data)

        assert req.request_id == "req-123"
        assert req.action == "ping"
        assert req.payload == {}

    def test_parse_request_with_payload(self):
        """Test parsing request with payload."""
        data = json.dumps({
            "request_id": "req-124",
            "action": "create_session",
            "payload": {
                "password": "test",
                "scope": ["work/*"]
            }
        })

        req = parse_request(data)

        assert req.action == "create_session"
        assert req.payload["password"] == "test"
        assert req.payload["scope"] == ["work/*"]

    def test_parse_request_with_session_id(self):
        """Test parsing request with session_id."""
        data = json.dumps({
            "request_id": "req-125",
            "action": "get",
            "session_id": "vs-abc123",
            "payload": {"path": "work/api/key"}
        })

        req = parse_request(data)

        assert req.session_id == "vs-abc123"

    def test_parse_request_missing_action(self):
        """Test parsing request without action."""
        data = json.dumps({"request_id": "req-123"})

        with pytest.raises(ValueError, match="Missing required field: action"):
            parse_request(data)

    def test_parse_request_invalid_json(self):
        """Test parsing invalid JSON."""
        data = "not valid json"

        with pytest.raises(json.JSONDecodeError):
            parse_request(data)


class TestSerializeResponse:
    """Tests for response serialization."""

    def test_serialize_response_ok(self):
        """Test serializing success response."""
        resp = ok_response("req-123", {"session_id": "vs-abc"})

        data = serialize_response(resp)
        obj = json.loads(data)

        assert obj["request_id"] == "req-123"
        assert obj["status"] == "ok"
        assert obj["data"]["session_id"] == "vs-abc"

    def test_serialize_response_error(self):
        """Test serializing error response."""
        resp = error_response("req-123", "NO_SESSION", "Session not found")

        data = serialize_response(resp)
        obj = json.loads(data)

        assert obj["status"] == "error"
        assert obj["error"]["code"] == "NO_SESSION"
        assert obj["error"]["message"] == "Session not found"

    def test_serialize_response_no_data(self):
        """Test serializing response without data."""
        resp = Response(request_id="req-123", status="ok")

        data = serialize_response(resp)
        obj = json.loads(data)

        assert obj["status"] == "ok"
        assert "data" not in obj


class TestHandlePing:
    """Tests for ping handler."""

    def test_handle_ping(self):
        """Test ping handler returns version."""
        req = Request(request_id="ping-1", action="ping")

        resp = handle_ping(req)

        assert resp.status == "ok"
        assert resp.data["version"] == "2.0.0"


class TestHandleCreateSession:
    """Tests for create_session handler."""

    def test_handle_create_session_success(
        self, test_vault, clean_session_store, audit_logger, mock_pid_tree
    ):
        """Test successful session creation."""
        import threading
        req = Request(
            request_id="req-1",
            action="create_session",
            payload={
                "password": test_vault["password"],
                "scope": ["work/*"],
                "ttl": 3600,
                "root_pid": 1000,
                "command": "claude"
            }
        )

        lock = threading.Lock()

        resp = handle_create_session(
            req, clean_session_store, audit_logger, test_vault["path"], lock
        )

        assert resp.status == "ok"
        assert "session_id" in resp.data
        assert resp.data["session_id"].startswith("vs-")

    def test_handle_create_session_invalid_password(
        self, test_vault, clean_session_store, audit_logger, mock_pid_tree
    ):
        """Test session creation with wrong password."""
        import threading
        req = Request(
            request_id="req-1",
            action="create_session",
            payload={
                "password": "wrong_password",
                "scope": ["work/*"],
                "ttl": 3600,
                "root_pid": 1000,
                "command": "claude"
            }
        )

        lock = threading.Lock()

        resp = handle_create_session(
            req, clean_session_store, audit_logger, test_vault["path"], lock
        )

        assert resp.status == "error"
        assert resp.error["code"] == "INVALID_PASSWORD"

    def test_handle_create_session_missing_password(
        self, test_vault, clean_session_store, audit_logger
    ):
        """Test session creation without password."""
        import threading
        req = Request(
            request_id="req-1",
            action="create_session",
            payload={"scope": ["work/*"], "root_pid": 1000}
        )

        lock = threading.Lock()

        resp = handle_create_session(
            req, clean_session_store, audit_logger, test_vault["path"], lock
        )

        assert resp.status == "error"
        assert resp.error["code"] == "INVALID_REQUEST"


class TestHandleGet:
    """Tests for get handler."""

    def test_handle_get_allowed(
        self, test_vault, clean_session_store, audit_logger, mock_pid_tree
    ):
        """Test get within scope."""
        import threading
        # Create session first
        key = test_vault["key"]
        session = clean_session_store.create_session(
            root_pid=1000,
            derived_key=key,
            scope=["work/*"],
            ttl=3600,
            command="claude"
        )

        req = Request(
            request_id="req-1",
            action="get",
            session_id=session.session_id,
            payload={"path": "work/api/key", "client_pid": 1000}
        )

        lock = threading.Lock()

        resp = handle_get(req, clean_session_store, audit_logger, test_vault["path"], lock)

        assert resp.status == "ok"
        assert resp.data["secret"] == "sk_live_work_123"

    def test_handle_get_denied_out_of_scope(
        self, test_vault, clean_session_store, audit_logger, mock_pid_tree
    ):
        """Test get outside scope."""
        import threading
        key = test_vault["key"]
        session = clean_session_store.create_session(
            root_pid=1000,
            derived_key=key,
            scope=["work/*"],
            ttl=3600,
            command="claude"
        )

        req = Request(
            request_id="req-1",
            action="get",
            session_id=session.session_id,
            payload={"path": "personal/email/password", "client_pid": 1000}
        )

        lock = threading.Lock()

        resp = handle_get(req, clean_session_store, audit_logger, test_vault["path"], lock)

        assert resp.status == "error"
        assert resp.error["code"] == "ACCESS_DENIED"

    def test_handle_get_not_found(
        self, test_vault, clean_session_store, audit_logger, mock_pid_tree
    ):
        """Test get for non-existent entry."""
        import threading
        key = test_vault["key"]
        session = clean_session_store.create_session(
            root_pid=1000,
            derived_key=key,
            scope=["*"],
            ttl=3600,
            command="claude"
        )

        req = Request(
            request_id="req-1",
            action="get",
            session_id=session.session_id,
            payload={"path": "nonexistent/path", "client_pid": 1000}
        )

        lock = threading.Lock()

        resp = handle_get(req, clean_session_store, audit_logger, test_vault["path"], lock)

        assert resp.status == "error"
        assert resp.error["code"] == "NOT_FOUND"

    def test_handle_get_no_session(
        self, test_vault, clean_session_store, audit_logger
    ):
        """Test get without valid session."""
        import threading
        req = Request(
            request_id="req-1",
            action="get",
            session_id="vs-nonexistent",
            payload={"path": "work/api/key", "client_pid": 1000}
        )

        lock = threading.Lock()

        resp = handle_get(req, clean_session_store, audit_logger, test_vault["path"], lock)

        assert resp.status == "error"
        assert resp.error["code"] == "NO_SESSION"


class TestHandleDestroySession:
    """Tests for destroy_session handler."""

    def test_handle_destroy_session(
        self, clean_session_store, audit_logger, mock_pid_tree
    ):
        """Test destroying a session."""
        import threading
        key = b"x" * 32
        session = clean_session_store.create_session(
            root_pid=1000,
            derived_key=key,
            scope=["*"],
            ttl=3600,
            command="claude"
        )

        req = Request(
            request_id="req-1",
            action="destroy_session",
            payload={"session_id": session.session_id}
        )

        lock = threading.Lock()

        resp = handle_destroy_session(
            req, clean_session_store, audit_logger, None, lock
        )

        assert resp.status == "ok"
        assert resp.data["destroyed"] is True

    def test_handle_destroy_session_not_found(
        self, clean_session_store, audit_logger
    ):
        """Test destroying non-existent session."""
        import threading
        req = Request(
            request_id="req-1",
            action="destroy_session",
            payload={"session_id": "vs-nonexistent"}
        )

        lock = threading.Lock()

        resp = handle_destroy_session(
            req, clean_session_store, audit_logger, None, lock
        )

        assert resp.status == "error"
        assert resp.error["code"] == "NO_SESSION"


class TestHandleListSessions:
    """Tests for list_sessions handler."""

    def test_handle_list_sessions(
        self, clean_session_store, audit_logger, mock_pid_tree
    ):
        """Test listing sessions."""
        import threading
        key = b"x" * 32

        # Create sessions
        for i in range(3):
            clean_session_store.create_session(
                root_pid=1000 + i,
                derived_key=key,
                scope=["*"],
                ttl=3600,
                command="test"
            )

        req = Request(request_id="req-1", action="list_sessions")
        lock = threading.Lock()

        resp = handle_list_sessions(req, clean_session_store, audit_logger, None, lock)

        assert resp.status == "ok"
        assert len(resp.data["sessions"]) == 3

    def test_handle_list_sessions_empty(
        self, clean_session_store, audit_logger
    ):
        """Test listing when no sessions."""
        import threading
        req = Request(request_id="req-1", action="list_sessions")
        lock = threading.Lock()

        resp = handle_list_sessions(req, clean_session_store, audit_logger, None, lock)

        assert resp.status == "ok"
        assert resp.data["sessions"] == []


class TestHandleRequest:
    """Tests for main request handler."""

    def test_handle_request_ping(self):
        """Test routing ping request."""
        req = Request(request_id="req-1", action="ping")

        resp = handle_request(req, None, None, None, None)

        assert resp.status == "ok"
        assert resp.data["version"] == "2.0.0"

    def test_handle_request_unknown_action(self):
        """Test routing unknown action."""
        req = Request(request_id="req-1", action="unknown_action")

        resp = handle_request(req, None, None, None, None)

        assert resp.status == "error"
        assert "Unknown action" in resp.error["message"]


class TestErrorCodes:
    """Tests for error codes dictionary."""

    def test_error_codes_defined(self):
        """Test that expected error codes exist."""
        expected = [
            "OK", "INVALID_PASSWORD", "NO_SESSION", "ACCESS_DENIED",
            "NOT_FOUND", "ALREADY_EXISTS", "DAEMON_ERROR", "INVALID_REQUEST"
        ]

        for code in expected:
            assert code in ERROR_CODES

    def test_error_codes_have_messages(self):
        """Test that all error codes have messages."""
        for code, message in ERROR_CODES.items():
            assert isinstance(message, str)
            assert len(message) > 0
