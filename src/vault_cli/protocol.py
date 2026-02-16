#!/usr/bin/env python3
"""Unix Socket Protocol - JSON-based communication between CLI and daemon.

Defines request/response formats and action handlers for vault operations.
"""

import fnmatch
import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from .main import decrypt_secret, derive_key, encrypt_secret, get_metadata


@dataclass
class Request:
    """A request from CLI to daemon."""

    request_id: str
    action: str
    session_id: Optional[str] = None
    payload: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Response:
    """A response from daemon to CLI."""

    request_id: str
    status: str  # "ok" or "error"
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[Dict[str, str]] = None


# Error codes
ERROR_CODES = {
    "OK": "Success",
    "INVALID_PASSWORD": "Invalid master password",
    "NO_SESSION": "Session not found or expired",
    "ACCESS_DENIED": "Access denied",
    "NOT_FOUND": "Entry not found",
    "ALREADY_EXISTS": "Entry already exists",
    "DAEMON_ERROR": "Internal daemon error",
    "INVALID_REQUEST": "Malformed request",
    "DAEMON_NOT_RUNNING": "Vault daemon not running",
    "TIMEOUT": "Request timed out",
    "CONNECTION_ERROR": "Connection error",
    "MAX_SESSIONS": "Maximum sessions reached",
}


def parse_request(data: str) -> Request:
    """Parse a JSON request string.

    Args:
        data: JSON string

    Returns:
        Request object

    Raises:
        ValueError: If JSON is invalid or missing required fields

    """
    obj = json.loads(data)

    if "action" not in obj:
        raise ValueError("Missing required field: action")

    return Request(
        request_id=obj.get("request_id", ""),
        action=obj["action"],
        session_id=obj.get("session_id"),
        payload=obj.get("payload", {})
    )


def serialize_response(response: Response) -> str:
    """Serialize a response to JSON.

    Args:
        response: Response object

    Returns:
        JSON string

    """
    obj = {
        "request_id": response.request_id,
        "status": response.status,
    }

    if response.data:
        obj["data"] = response.data

    if response.error:
        obj["error"] = response.error

    return json.dumps(obj)


def error_response(request_id: str, code: str, message: Optional[str] = None) -> Response:
    """Create an error response."""
    return Response(
        request_id=request_id,
        status="error",
        error={
            "code": code,
            "message": message or ERROR_CODES.get(code, "Unknown error")
        }
    )


def ok_response(request_id: str, data: Dict[str, Any]) -> Response:
    """Create a success response."""
    return Response(
        request_id=request_id,
        status="ok",
        data=data
    )


def handle_request(
    request: Request,
    session_store,
    audit_logger,
    vault_path: Path,
    lock
) -> Response:
    """Handle a request and return a response.

    Routes to the appropriate action handler based on request.action.
    """
    handlers = {
        "ping": handle_ping,
        "create_session": handle_create_session,
        "destroy_session": handle_destroy_session,
        "list_sessions": handle_list_sessions,
        "get": handle_get,
        "add": handle_add,
        "delete": handle_delete,
        "list": handle_list,
    }

    handler = handlers.get(request.action)
    if not handler:
        return error_response(request.request_id, "INVALID_REQUEST", f"Unknown action: {request.action}")

    return handler(request, session_store, audit_logger, vault_path, lock)


def handle_ping(request: Request, *args) -> Response:
    """Handle ping request."""
    return ok_response(request.request_id, {"version": "2.0.0", "status": "ok"})


def handle_create_session(
    request: Request,
    session_store,
    audit_logger,
    vault_path: Path,
    lock
) -> Response:
    """Handle create_session request."""
    payload = request.payload

    password = payload.get("password")
    scope = payload.get("scope", [])
    ttl = payload.get("ttl", 1800)
    root_pid = payload.get("root_pid")
    command = payload.get("command", "unknown")

    if not password:
        return error_response(request.request_id, "INVALID_REQUEST", "Missing password")

    if not root_pid:
        return error_response(request.request_id, "INVALID_REQUEST", "Missing root_pid")

    # Verify password and get derived key
    try:
        conn = sqlite3.connect(vault_path)
        metadata = get_metadata(conn)
        conn.close()

        if not metadata:
            return error_response(request.request_id, "DAEMON_ERROR", "Invalid vault")

        key = derive_key(password, metadata['salt'])

        # Verify canary
        canary = decrypt_secret(key, metadata['canary_ciphertext'], metadata['canary_nonce'])
        if canary != "VAULT_CANARY":
            audit_logger.log_access(
                pid=root_pid,
                command=command,
                result="DENIED",
                action="CREATE_SESSION",
                path="-",
                reason="invalid-password"
            )
            return error_response(request.request_id, "INVALID_PASSWORD")

    except Exception as e:
        audit_logger.log_access(
            pid=root_pid,
            command=command,
            result="ERROR",
            action="CREATE_SESSION",
            path="-",
            reason=str(e)
        )
        return error_response(request.request_id, "INVALID_PASSWORD")

    # Create session
    try:
        with lock:
            session = session_store.create_session(
                root_pid=root_pid,
                derived_key=key,
                scope=scope,
                ttl=ttl,
                command=command
            )

        audit_logger.log_access(
            pid=root_pid,
            command=command,
            result="ALLOWED",
            action="CREATE_SESSION",
            path=session.session_id
        )

        return ok_response(request.request_id, {
            "session_id": session.session_id,
            "expires_at": session.expires_at.isoformat()
        })

    except ValueError as e:
        return error_response(request.request_id, "MAX_SESSIONS", str(e))


def handle_destroy_session(
    request: Request,
    session_store,
    audit_logger,
    vault_path: Path,
    lock
) -> Response:
    """Handle destroy_session request."""
    session_id = request.payload.get("session_id")

    if not session_id:
        return error_response(request.request_id, "INVALID_REQUEST", "Missing session_id")

    with lock:
        session = session_store.get_session(session_id)
        if not session:
            return error_response(request.request_id, "NO_SESSION")

        session_store.destroy_session(session_id)

    audit_logger.log_access(
        pid=session.root_pid,
        command=session.command,
        result="REVOKED",
        action="SESSION",
        path=session_id,
        reason="user-request"
    )

    return ok_response(request.request_id, {"destroyed": True})


def handle_list_sessions(
    request: Request,
    session_store,
    audit_logger,
    vault_path: Path,
    lock
) -> Response:
    """Handle list_sessions request."""
    with lock:
        sessions = session_store.list_sessions()

    session_data = []
    for s in sessions:
        session_data.append({
            "session_id": s.session_id,
            "root_pid": s.root_pid,
            "command": s.command,
            "scope": s.scope,
            "created_at": s.created_at.isoformat(),
            "expires_at": s.expires_at.isoformat(),
            "access_count_allowed": s.access_count_allowed,
            "access_count_denied": s.access_count_denied,
        })

    return ok_response(request.request_id, {"sessions": session_data})


def handle_get(
    request: Request,
    session_store,
    audit_logger,
    vault_path: Path,
    lock
) -> Response:
    """Handle get request."""
    session_id = request.session_id
    payload = request.payload

    path = payload.get("path")
    client_pid = payload.get("client_pid")

    if not session_id:
        return error_response(request.request_id, "NO_SESSION")

    if not path:
        return error_response(request.request_id, "INVALID_REQUEST", "Missing path")

    if not client_pid:
        return error_response(request.request_id, "INVALID_REQUEST", "Missing client_pid")

    # Validate access
    with lock:
        allowed, session, reason = session_store.validate_access(
            session_id, client_pid, path
        )

    if not session:
        audit_logger.log_access(
            pid=client_pid,
            command="unknown",
            result="DENIED",
            action="GET",
            path=path,
            reason="no-session"
        )
        return error_response(request.request_id, "NO_SESSION")

    if not allowed:
        audit_logger.log_access(
            pid=client_pid,
            command=session.command,
            result="DENIED",
            action="GET",
            path=path,
            reason=reason
        )
        return error_response(
            request.request_id,
            "ACCESS_DENIED" if reason == "out-of-scope" else "NO_SESSION",
            f"Access denied: {reason}"
        )

    # Get secret from database
    try:
        conn = sqlite3.connect(vault_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT ciphertext, nonce FROM entries WHERE path = ?",
            (path,)
        )
        row = cursor.fetchone()
        conn.close()

        if not row:
            audit_logger.log_access(
                pid=client_pid,
                command=session.command,
                result="DENIED",
                action="GET",
                path=path,
                reason="not-found"
            )
            return error_response(request.request_id, "NOT_FOUND", f"Entry not found: {path}")

        plaintext = decrypt_secret(session.derived_key, row[0], row[1])
        data = json.loads(plaintext)

        audit_logger.log_access(
            pid=client_pid,
            command=session.command,
            result="ALLOWED",
            action="GET",
            path=path
        )

        return ok_response(request.request_id, {
            "secret": data.get("secret"),
            "note": data.get("note", "")
        })

    except Exception as e:
        audit_logger.log_access(
            pid=client_pid,
            command=session.command,
            result="ERROR",
            action="GET",
            path=path,
            reason=str(e)
        )
        return error_response(request.request_id, "DAEMON_ERROR", str(e))


def handle_add(
    request: Request,
    session_store,
    audit_logger,
    vault_path: Path,
    lock
) -> Response:
    """Handle add request."""
    session_id = request.session_id
    payload = request.payload

    path = payload.get("path")
    secret = payload.get("secret")
    note = payload.get("note", "")
    client_pid = payload.get("client_pid")

    if not session_id:
        return error_response(request.request_id, "NO_SESSION")

    if not path or secret is None:
        return error_response(request.request_id, "INVALID_REQUEST", "Missing path or secret")

    if not client_pid:
        return error_response(request.request_id, "INVALID_REQUEST", "Missing client_pid")

    # Validate access (need write permission)
    with lock:
        allowed, session, reason = session_store.validate_access(
            session_id, client_pid, path
        )

    if not session:
        audit_logger.log_access(
            pid=client_pid,
            command="unknown",
            result="DENIED",
            action="ADD",
            path=path,
            reason="no-session"
        )
        return error_response(request.request_id, "NO_SESSION")

    if not allowed:
        audit_logger.log_access(
            pid=client_pid,
            command=session.command,
            result="DENIED",
            action="ADD",
            path=path,
            reason=reason
        )
        return error_response(request.request_id, "ACCESS_DENIED", f"Access denied: {reason}")

    # Add secret to database
    try:
        data = {"secret": secret, "note": note}
        plaintext = json.dumps(data)
        ciphertext, nonce = encrypt_secret(session.derived_key, plaintext)

        now = datetime.now(timezone.utc).isoformat()

        conn = sqlite3.connect(vault_path)
        cursor = conn.cursor()

        # Check if entry exists to preserve created timestamp
        cursor.execute("SELECT created FROM entries WHERE path = ?", (path,))
        row = cursor.fetchone()
        created = row[0] if row else now

        cursor.execute(
            """INSERT OR REPLACE INTO entries (path, ciphertext, nonce, created, modified)
               VALUES (?, ?, ?, ?, ?)""",
            (path, ciphertext, nonce, created, now)
        )
        conn.commit()
        conn.close()

        audit_logger.log_access(
            pid=client_pid,
            command=session.command,
            result="ALLOWED",
            action="ADD",
            path=path
        )

        return ok_response(request.request_id, {"saved": True})

    except Exception as e:
        audit_logger.log_access(
            pid=client_pid,
            command=session.command,
            result="ERROR",
            action="ADD",
            path=path,
            reason=str(e)
        )
        return error_response(request.request_id, "DAEMON_ERROR", str(e))


def handle_delete(
    request: Request,
    session_store,
    audit_logger,
    vault_path: Path,
    lock
) -> Response:
    """Handle delete request."""
    session_id = request.session_id
    payload = request.payload

    path = payload.get("path")
    client_pid = payload.get("client_pid")

    if not session_id:
        return error_response(request.request_id, "NO_SESSION")

    if not path:
        return error_response(request.request_id, "INVALID_REQUEST", "Missing path")

    if not client_pid:
        return error_response(request.request_id, "INVALID_REQUEST", "Missing client_pid")

    # Validate access
    with lock:
        allowed, session, reason = session_store.validate_access(
            session_id, client_pid, path
        )

    if not session:
        audit_logger.log_access(
            pid=client_pid,
            command="unknown",
            result="DENIED",
            action="DELETE",
            path=path,
            reason="no-session"
        )
        return error_response(request.request_id, "NO_SESSION")

    if not allowed:
        audit_logger.log_access(
            pid=client_pid,
            command=session.command,
            result="DENIED",
            action="DELETE",
            path=path,
            reason=reason
        )
        return error_response(request.request_id, "ACCESS_DENIED", f"Access denied: {reason}")

    # Delete from database
    try:
        conn = sqlite3.connect(vault_path)
        cursor = conn.cursor()

        cursor.execute("SELECT 1 FROM entries WHERE path = ?", (path,))
        if not cursor.fetchone():
            conn.close()
            return error_response(request.request_id, "NOT_FOUND", f"Entry not found: {path}")

        cursor.execute("DELETE FROM entries WHERE path = ?", (path,))
        conn.commit()
        conn.close()

        audit_logger.log_access(
            pid=client_pid,
            command=session.command,
            result="ALLOWED",
            action="DELETE",
            path=path
        )

        return ok_response(request.request_id, {"deleted": True})

    except Exception as e:
        audit_logger.log_access(
            pid=client_pid,
            command=session.command,
            result="ERROR",
            action="DELETE",
            path=path,
            reason=str(e)
        )
        return error_response(request.request_id, "DAEMON_ERROR", str(e))


def handle_list(
    request: Request,
    session_store,
    audit_logger,
    vault_path: Path,
    lock
) -> Response:
    """Handle list request."""
    session_id = request.session_id
    payload = request.payload

    prefix = payload.get("path", "")
    client_pid = payload.get("client_pid")

    if not session_id:
        return error_response(request.request_id, "NO_SESSION")

    if not client_pid:
        return error_response(request.request_id, "INVALID_REQUEST", "Missing client_pid")

    # Validate access (need at least some scope)
    with lock:
        session = session_store.get_session(session_id)

    if not session:
        return error_response(request.request_id, "NO_SESSION")

    # List entries that match scope and prefix
    try:
        conn = sqlite3.connect(vault_path)
        cursor = conn.cursor()

        if prefix:
            prefix_path = prefix if prefix.endswith('/') else prefix + '/'
            cursor.execute(
                "SELECT path FROM entries WHERE path = ? OR path LIKE ? ORDER BY path",
                (prefix, prefix_path + '%')
            )
        else:
            cursor.execute("SELECT path FROM entries ORDER BY path")

        all_paths = [row[0] for row in cursor.fetchall()]
        conn.close()

        # Filter by scope
        filtered_paths = []
        for p in all_paths:
            for pattern in session.scope:
                if fnmatch.fnmatch(p, pattern):
                    filtered_paths.append(p)
                    break

        audit_logger.log_access(
            pid=client_pid,
            command=session.command,
            result="ALLOWED",
            action="LIST",
            path=prefix or "-"
        )

        return ok_response(request.request_id, {"paths": filtered_paths})

    except Exception as e:
        return error_response(request.request_id, "DAEMON_ERROR", str(e))
