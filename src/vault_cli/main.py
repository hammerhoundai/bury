#!/usr/bin/env python3
"""Vault CLI - A minimal, secure, hierarchical password/secrets manager.
Uses SQLite storage and libsodium cryptography via pynacl.

Version 2.0 adds PID-bound sessions for AI agent security.
"""

import argparse
import base64
import getpass
import json
import os
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path

import nacl.pwhash
import nacl.secret
import nacl.utils

# Constants
DEFAULT_VAULT = Path.home() / ".vault"
SESSION_FILE = Path.home() / ".vault-session"
SALT_SIZE = 16
NONCE_SIZE = 24
KEY_SIZE = 32
OPS_LIMIT = nacl.pwhash.OPSLIMIT_INTERACTIVE
MEM_LIMIT = nacl.pwhash.MEMLIMIT_INTERACTIVE


def get_vault_path(args_vault=None):
    """Get vault path from args or default."""
    return Path(args_vault) if args_vault else DEFAULT_VAULT


def get_password(prompt="Enter master password: "):
    """Get password from environment variable or prompt.

    Checks VAULT_PASSWORD environment variable first for automation/testing.
    Falls back to interactive getpass prompt if not set.

    Security note: Using VAULT_PASSWORD in environment variables is less secure
    as it may be visible in process lists. Only use in isolated environments.
    """
    env_password = os.environ.get('VAULT_PASSWORD')
    if env_password:
        return env_password
    return getpass.getpass(prompt)


def set_permissions(path, mode=0o600):
    """Set file permissions."""
    os.chmod(path, mode)


def derive_key(password, salt):
    """Derive encryption key from password using Argon2id."""
    return nacl.pwhash.argon2id.kdf(
        KEY_SIZE,
        password.encode('utf-8'),
        salt,
        opslimit=OPS_LIMIT,
        memlimit=MEM_LIMIT
    )


def encrypt_secret(key, plaintext):
    """Encrypt plaintext using SecretBox with fresh nonce."""
    box = nacl.secret.SecretBox(key)
    nonce = nacl.utils.random(NONCE_SIZE)
    ciphertext_with_nonce = box.encrypt(plaintext.encode('utf-8'), nonce)
    # ciphertext_with_nonce is nonce (24) + mac (16) + ciphertext
    # Return just the mac + ciphertext part, nonce separately
    ciphertext = ciphertext_with_nonce[NONCE_SIZE:]
    return ciphertext, nonce


def decrypt_secret(key, ciphertext, nonce):
    """Decrypt ciphertext using SecretBox."""
    box = nacl.secret.SecretBox(key)
    plaintext = box.decrypt(ciphertext, nonce)
    return plaintext.decode('utf-8')


def init_db(vault_path):
    """Initialize vault database schema."""
    conn = sqlite3.connect(vault_path)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE metadata (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            salt BLOB NOT NULL,
            opslimit INTEGER NOT NULL,
            memlimit INTEGER NOT NULL,
            canary_ciphertext BLOB NOT NULL,
            canary_nonce BLOB NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE entries (
            path TEXT PRIMARY KEY,
            ciphertext BLOB NOT NULL,
            nonce BLOB NOT NULL,
            created TEXT,
            modified TEXT
        )
    """)

    conn.commit()
    conn.close()


def get_metadata(conn):
    """Get vault metadata."""
    cursor = conn.cursor()
    cursor.execute("SELECT salt, opslimit, memlimit, canary_ciphertext, canary_nonce FROM metadata WHERE id = 1")
    row = cursor.fetchone()
    if not row:
        return None
    return {'salt': row[0], 'opslimit': row[1], 'memlimit': row[2], 'canary_ciphertext': row[3], 'canary_nonce': row[4]}


def cmd_init(args):
    """Create a new vault file."""
    vault_path = get_vault_path(args.vault)

    if vault_path.exists():
        print(f"Vault already exists: {vault_path}", file=sys.stderr)
        sys.exit(1)

    password = get_password("Enter master password: ")
    confirm = get_password("Confirm master password: ")

    if password != confirm:
        print("Passwords do not match", file=sys.stderr)
        sys.exit(1)

    # Generate salt and create vault
    salt = nacl.utils.random(SALT_SIZE)
    init_db(vault_path)

    # Derive key and create canary for password verification
    key = derive_key(password, salt)
    canary_ciphertext, canary_nonce = encrypt_secret(key, "VAULT_CANARY")

    conn = sqlite3.connect(vault_path)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO metadata (id, salt, opslimit, memlimit, canary_ciphertext, canary_nonce) VALUES (1, ?, ?, ?, ?, ?)",
        (salt, OPS_LIMIT, MEM_LIMIT, canary_ciphertext, canary_nonce)
    )
    conn.commit()
    conn.close()

    set_permissions(vault_path)
    print(f"Vault created at {vault_path}")


def unlock_vault(vault_path, password):
    """Unlock vault and return derived key."""
    if not vault_path.exists():
        print(f"Vault not found: {vault_path}", file=sys.stderr)
        sys.exit(1)

    conn = sqlite3.connect(vault_path)
    metadata = get_metadata(conn)
    conn.close()

    if not metadata:
        print("Invalid vault format", file=sys.stderr)
        sys.exit(1)

    try:
        key = derive_key(password, metadata['salt'])
        # Verify password by decrypting canary
        canary = decrypt_secret(key, metadata['canary_ciphertext'], metadata['canary_nonce'])
        if canary != "VAULT_CANARY":
            raise ValueError("Invalid canary")
        return key
    except Exception:
        print("Invalid password", file=sys.stderr)
        sys.exit(1)


def cmd_unlock(args):
    """Unlock vault and create session."""
    vault_path = get_vault_path(args.vault)
    password = get_password("Enter master password: ")

    key = unlock_vault(vault_path, password)

    ttl = args.ttl if args.ttl else 1800
    expires = datetime.now(timezone.utc).timestamp() + ttl

    session = {
        'key': base64.b64encode(key).decode('utf-8'),
        'expires': datetime.fromtimestamp(expires, tz=timezone.utc).isoformat()
    }

    with open(SESSION_FILE, 'w') as f:
        json.dump(session, f)
    set_permissions(SESSION_FILE)

    print(f"Session active ({ttl} seconds)")


def cmd_lock(args):
    """Destroy active vault session(s)."""
    vault_path = get_vault_path(args.vault)

    # Try daemon sessions first
    from .daemon import ping_daemon, send_request

    if ping_daemon():
        # Revoke all daemon sessions
        sessions_response = send_request({
            "request_id": "lock-list",
            "action": "list_sessions"
        })

        if sessions_response.get("status") == "ok":
            sessions = sessions_response["data"]["sessions"]
            revoked_count = 0

            for s in sessions:
                revoke_response = send_request({
                    "request_id": f"lock-{s['session_id']}",
                    "action": "destroy_session",
                    "payload": {"session_id": s["session_id"]}
                })
                if revoke_response.get("status") == "ok":
                    revoked_count += 1

            if revoked_count > 0:
                print(f"Locked: {revoked_count} session{'s' if revoked_count != 1 else ''} revoked")
            else:
                print("No active sessions to lock")
            return

    # Fall back to legacy session
    if SESSION_FILE.exists():
        SESSION_FILE.unlink()
        print("Session destroyed.")
    else:
        print("No active session.")


def load_session():
    """Load and validate session file."""
    if not SESSION_FILE.exists():
        return None

    try:
        with open(SESSION_FILE) as f:
            session = json.load(f)

        expires = datetime.fromisoformat(session['expires'])
        now = datetime.now(timezone.utc)

        if now > expires:
            SESSION_FILE.unlink()
            return None

        return base64.b64decode(session['key'])
    except (json.JSONDecodeError, KeyError, ValueError):
        SESSION_FILE.unlink()
        return None


def get_key_or_unlock(vault_path, password=None):
    """Get key from session or prompt for password."""
    key = load_session()
    if key:
        return key

    if password:
        return unlock_vault(vault_path, password)

    if sys.stdin.isatty():
        password = get_password("Enter master password: ")
        return unlock_vault(vault_path, password)

    print("No active session. Run 'vault unlock' first.", file=sys.stderr)
    sys.exit(1)


def cmd_add(args):
    """Add or overwrite an entry."""
    vault_path = get_vault_path(args.vault)

    if not vault_path.exists():
        print(f"Vault not found: {vault_path}", file=sys.stderr)
        sys.exit(1)

    key = get_key_or_unlock(vault_path)
    secret = getpass.getpass("Enter secret: ")

    data = {'secret': secret, 'note': args.note or ''}
    plaintext = json.dumps(data)

    ciphertext, nonce = encrypt_secret(key, plaintext)

    now = datetime.now(timezone.utc).isoformat()

    conn = sqlite3.connect(vault_path)
    cursor = conn.cursor()

    # Check if entry exists
    cursor.execute("SELECT created FROM entries WHERE path = ?", (args.path,))
    row = cursor.fetchone()
    created = row[0] if row else now

    cursor.execute(
        """INSERT OR REPLACE INTO entries (path, ciphertext, nonce, created, modified)
           VALUES (?, ?, ?, ?, ?)""",
        (args.path, ciphertext, nonce, created, now)
    )
    conn.commit()
    conn.close()

    print("Saved.")


def cmd_get(args):
    """Retrieve an entry."""
    vault_path = get_vault_path(args.vault)

    if not vault_path.exists():
        print(f"Vault not found: {vault_path}", file=sys.stderr)
        sys.exit(1)

    # Check for PID-bound session first
    session_id = os.environ.get("VAULT_SESSION_ID")
    if session_id:
        # Use daemon
        from .daemon import send_request

        request = {
            "request_id": f"req-get-{os.getpid()}",
            "action": "get",
            "session_id": session_id,
            "payload": {
                "path": args.path,
                "client_pid": os.getpid()
            }
        }

        response = send_request(request)

        if response.get("status") == "ok":
            secret = response["data"]["secret"]
            if args.show:
                print(secret)
            else:
                copy_to_clipboard(secret)
            return
        else:
            error = response.get("error", {})
            code = error.get("code", "UNKNOWN")
            message = error.get("message", "Unknown error")

            if code == "ACCESS_DENIED":
                print(f"Access denied: path '{args.path}' not in session scope", file=sys.stderr)
            elif code == "NO_SESSION":
                print("Session expired. Run 'vault agent <command>' to create new session", file=sys.stderr)
            elif code == "NOT_FOUND":
                print(f"Entry not found: {args.path}", file=sys.stderr)
            else:
                print(f"Error: {message}", file=sys.stderr)
            sys.exit(1)

    # Fall back to legacy session
    conn = sqlite3.connect(vault_path)
    cursor = conn.cursor()
    cursor.execute("SELECT ciphertext, nonce FROM entries WHERE path = ?", (args.path,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        print(f"Entry not found: {args.path}", file=sys.stderr)
        sys.exit(1)

    key = get_key_or_unlock(vault_path)

    try:
        plaintext = decrypt_secret(key, row[0], row[1])
        data = json.loads(plaintext)
        secret = data['secret']
    except Exception:
        print("Invalid password", file=sys.stderr)
        sys.exit(1)

    if args.show:
        print(secret)
    else:
        copy_to_clipboard(secret)


def copy_to_clipboard(text):
    """Copy text to clipboard using appropriate tool."""
    # Detect environment and choose tool
    if os.path.exists("/proc/version"):
        with open("/proc/version") as f:
            version = f.read().lower()
            if "microsoft" in version or "wsl" in version:
                cmd = ["clip.exe"]
            else:
                # Check for Wayland
                if os.environ.get("WAYLAND_DISPLAY"):
                    cmd = ["wl-copy"]
                else:
                    cmd = ["xclip", "-selection", "clipboard"]
    elif sys.platform == "darwin":
        cmd = ["pbcopy"]
    else:
        print(f"Secret: {text}")
        print("(No clipboard tool available - printing to stdout)", file=sys.stderr)
        return

    try:
        proc = subprocess.run(cmd, input=text.encode('utf-8'), capture_output=True)
        if proc.returncode == 0:
            print("(copied to clipboard)")
        else:
            print(f"Secret: {text}")
            print("(Clipboard failed - printing to stdout)", file=sys.stderr)
    except FileNotFoundError:
        print(f"Secret: {text}")
        print("(Clipboard tool not found - printing to stdout)", file=sys.stderr)


def cmd_list(args):
    """List entries."""
    vault_path = get_vault_path(args.vault)

    if not vault_path.exists():
        print(f"Vault not found: {vault_path}", file=sys.stderr)
        sys.exit(1)

    conn = sqlite3.connect(vault_path)
    cursor = conn.cursor()

    if args.path:
        prefix = args.path if args.path.endswith('/') else args.path + '/'
        cursor.execute("SELECT path FROM entries WHERE path = ? OR path LIKE ? ORDER BY path",
                       (args.path, prefix + '%'))
    else:
        cursor.execute("SELECT path FROM entries ORDER BY path")

    rows = cursor.fetchall()
    conn.close()

    for row in rows:
        print(row[0])


def cmd_delete(args):
    """Delete an entry."""
    vault_path = get_vault_path(args.vault)

    if not vault_path.exists():
        print(f"Vault not found: {vault_path}", file=sys.stderr)
        sys.exit(1)

    conn = sqlite3.connect(vault_path)
    cursor = conn.cursor()

    cursor.execute("SELECT 1 FROM entries WHERE path = ?", (args.path,))
    if not cursor.fetchone():
        print(f"Entry not found: {args.path}", file=sys.stderr)
        conn.close()
        sys.exit(1)

    cursor.execute("DELETE FROM entries WHERE path = ?", (args.path,))
    conn.commit()
    conn.close()

    print("Deleted.")


def cmd_tree(args):
    """Display hierarchical structure."""
    vault_path = get_vault_path(args.vault)

    if not vault_path.exists():
        print(f"Vault not found: {vault_path}", file=sys.stderr)
        sys.exit(1)

    conn = sqlite3.connect(vault_path)
    cursor = conn.cursor()
    cursor.execute("SELECT path FROM entries ORDER BY path")
    paths = [row[0] for row in cursor.fetchall()]
    conn.close()

    if not paths:
        return

    # Build tree structure
    tree = {}
    for path in paths:
        parts = path.split('/')
        node = tree
        for part in parts:
            if part not in node:
                node[part] = {}
            node = node[part]

    # Print tree
    def print_tree(node, prefix='', is_last=True):
        items = list(node.items())
        for i, (name, children) in enumerate(items):
            is_last_item = i == len(items) - 1
            connector = "└── " if is_last_item else "├── "
            print(f"{prefix}{connector}{name}")
            if children:
                extension = "    " if is_last_item else "│   "
                print_tree(children, prefix + extension, is_last_item)

    print_tree(tree, prefix='', is_last=True)


def cmd_mv(args):
    """Move/rename an entry."""
    vault_path = get_vault_path(args.vault)

    if not vault_path.exists():
        print(f"Vault not found: {vault_path}", file=sys.stderr)
        sys.exit(1)

    conn = sqlite3.connect(vault_path)
    cursor = conn.cursor()

    # Check old path exists
    cursor.execute("SELECT created, ciphertext, nonce FROM entries WHERE path = ?", (args.old_path,))
    row = cursor.fetchone()
    if not row:
        print(f"Entry not found: {args.old_path}", file=sys.stderr)
        conn.close()
        sys.exit(1)

    created, ciphertext, nonce = row

    # Check new path doesn't exist
    cursor.execute("SELECT 1 FROM entries WHERE path = ?", (args.new_path,))
    if cursor.fetchone():
        print(f"Entry already exists: {args.new_path}", file=sys.stderr)
        conn.close()
        sys.exit(1)

    now = datetime.now(timezone.utc).isoformat()

    cursor.execute(
        "INSERT INTO entries (path, ciphertext, nonce, created, modified) VALUES (?, ?, ?, ?, ?)",
        (args.new_path, ciphertext, nonce, created, now)
    )
    cursor.execute("DELETE FROM entries WHERE path = ?", (args.old_path,))

    conn.commit()
    conn.close()

    print("Moved.")


def cmd_search(args):
    """Search entries."""
    vault_path = get_vault_path(args.vault)

    if not vault_path.exists():
        print(f"Vault not found: {vault_path}", file=sys.stderr)
        sys.exit(1)

    conn = sqlite3.connect(vault_path)
    cursor = conn.cursor()
    cursor.execute("SELECT path FROM entries ORDER BY path")
    paths = [row[0] for row in cursor.fetchall()]
    conn.close()

    term = args.term.lower()
    for path in paths:
        if term in path.lower():
            print(path)


def cmd_proxy(args):
    """Execute command with credential substitution."""
    vault_path = get_vault_path(args.vault)

    if not vault_path.exists():
        print(f"Vault not found: {vault_path}", file=sys.stderr)
        sys.exit(1)

    key = get_key_or_unlock(vault_path)

    # Decrypt all credentials we might need
    conn = sqlite3.connect(vault_path)
    cursor = conn.cursor()
    cursor.execute("SELECT path, ciphertext, nonce FROM entries")
    entries = {row[0]: (row[1], row[2]) for row in cursor.fetchall()}
    conn.close()

    credentials = {}
    for path, (ciphertext, nonce) in entries.items():
        try:
            plaintext = decrypt_secret(key, ciphertext, nonce)
            data = json.loads(plaintext)
            credentials[path] = data['secret']
        except Exception:
            pass

    # Substitute [CRED:path] patterns in arguments
    import re
    pattern = re.compile(r'\[CRED:([^\]]+)\]')

    new_args = []
    for arg in args.cmd_args:
        new_arg = pattern.sub(lambda m: credentials.get(m.group(1), m.group(0)), arg)
        new_args.append(new_arg)

    # Execute command
    os.execvp(args.cmd[0], [args.cmd[0]] + new_args)


# ============================================================================
# PID-Bound Session Commands (v2.0)
# ============================================================================

def cmd_daemon(args):
    """Start or stop the vault daemon."""
    from .daemon import VaultDaemon

    vault_path = get_vault_path(args.vault)
    daemon = VaultDaemon(vault_path, foreground=args.foreground)

    if args.stop:
        if daemon.stop():
            sys.exit(0)
        else:
            sys.exit(1)
    else:
        if daemon.start():
            sys.exit(0)
        else:
            sys.exit(1)


def cmd_agent(args):
    """Launch a command with a vault session."""
    vault_path = get_vault_path(args.vault)

    if not vault_path.exists():
        print(f"Vault not found: {vault_path}", file=sys.stderr)
        sys.exit(1)

    # Check if daemon is running
    from .daemon import ping_daemon, send_request
    if not ping_daemon():
        print("Vault daemon not running. Start with: vault daemon", file=sys.stderr)
        sys.exit(1)

    # Get password
    password = get_password("Enter master password: ")

    # Build scope list
    scope = args.allow if args.allow else ["*"]
    ttl = args.ttl if args.ttl else 1800

    # Strip leading '--' from cmd if present (used to separate flags from command)
    cmd = args.cmd
    if cmd and cmd[0] == '--':
        cmd = cmd[1:]

    # Create session
    import uuid
    request = {
        "request_id": f"req-{uuid.uuid4().hex[:8]}",
        "action": "create_session",
        "payload": {
            "password": password,
            "scope": scope,
            "ttl": ttl,
            "root_pid": os.getpid(),
            "command": cmd[0] if cmd else "unknown"
        }
    }

    response = send_request(request)

    if response.get("status") != "ok":
        error = response.get("error", {})
        print(f"Error: {error.get('message', 'Unknown error')}", file=sys.stderr)
        sys.exit(1)

    session_id = response["data"]["session_id"]

    # Build environment
    env = os.environ.copy()
    env["VAULT_SESSION_ID"] = session_id

    # Launch command
    if not cmd:
        print(f"Session created: {session_id}")
        print(f"Expires in {ttl} seconds")
        print("Set VAULT_SESSION_ID environment variable to use:")
        print(f"  export VAULT_SESSION_ID={session_id}")
        sys.exit(0)

    try:
        # Use subprocess to launch with the session environment
        os.execvpe(cmd[0], cmd, env)
    except FileNotFoundError:
        print(f"Command not found: {cmd[0]}", file=sys.stderr)
        sys.exit(1)


def get_session_secret(vault_path: Path, path: str) -> tuple:
    """Get a secret using PID-bound session if available.

    Returns (secret, note) tuple.
    Raises SystemExit on error.
    """
    session_id = os.environ.get("VAULT_SESSION_ID")

    if session_id:
        # Use daemon
        from .daemon import send_request

        request = {
            "request_id": f"req-{os.getpid()}",
            "action": "get",
            "session_id": session_id,
            "payload": {
                "path": path,
                "client_pid": os.getpid()
            }
        }

        response = send_request(request)

        if response.get("status") == "ok":
            return response["data"]["secret"], response["data"].get("note", "")
        else:
            error = response.get("error", {})
            code = error.get("code", "UNKNOWN")
            message = error.get("message", "Unknown error")

            if code == "ACCESS_DENIED":
                print(f"Access denied: path '{path}' not in session scope", file=sys.stderr)
            elif code == "NO_SESSION":
                print("Session expired. Run 'vault agent <command>' to create new session", file=sys.stderr)
            else:
                print(f"Error: {message}", file=sys.stderr)
            sys.exit(1)
    else:
        # Use legacy session
        return None, None


def cmd_status(args):
    """Show active sessions."""
    from .daemon import ping_daemon, send_request

    if not ping_daemon():
        print("Vault daemon not running", file=sys.stderr)
        sys.exit(1)

    request = {
        "request_id": "status",
        "action": "list_sessions"
    }

    response = send_request(request)

    if response.get("status") != "ok":
        print(f"Error: {response.get('error', {}).get('message', 'Unknown error')}", file=sys.stderr)
        sys.exit(1)

    sessions = response["data"]["sessions"]

    if args.json:
        print(json.dumps({
            "vault_state": "unlocked",
            "session_count": len(sessions),
            "sessions": sessions
        }, indent=2))
    else:
        if not sessions:
            print("Vault: UNLOCKED (no active sessions)")
            return

        print(f"Vault: UNLOCKED ({len(sessions)} active session{'s' if len(sessions) != 1 else ''})")
        print()

        for s in sessions:
            expires_in = int((datetime.fromisoformat(s["expires_at"].replace("Z", "+00:00"))
                             - datetime.now(timezone.utc)).total_seconds() / 60)
            print(f"Session: {s['session_id']}")
            print(f"  PID: {s['root_pid']} ({s['command']})")
            print(f"  Scope: {', '.join(s['scope'])}")
            print(f"  Expires: {expires_in} mins")
            print(f"  Accesses: {s['access_count_allowed']} allowed, {s['access_count_denied']} denied")
            print()


def cmd_revoke(args):
    """Revoke a specific session."""
    from .daemon import ping_daemon, send_request

    if not ping_daemon():
        print("Vault daemon not running", file=sys.stderr)
        sys.exit(1)

    request = {
        "request_id": "revoke",
        "action": "destroy_session",
        "payload": {
            "session_id": args.session_id
        }
    }

    response = send_request(request)

    if response.get("status") == "ok":
        print(f"Session {args.session_id} revoked")
    else:
        error = response.get("error", {})
        print(f"Error: {error.get('message', 'Unknown error')}", file=sys.stderr)
        sys.exit(1)


def cmd_migrate_env(args):
    """Migrate .env file to vault."""
    import re
    import shutil

    vault_path = get_vault_path(args.vault)
    env_file = Path(args.env_file)

    if not env_file.exists():
        print(f"Env file not found: {env_file}", file=sys.stderr)
        sys.exit(1)

    # Check for active session
    session_id = os.environ.get("VAULT_SESSION_ID")
    if not session_id:
        print("No active session. Run 'vault agent <command>' first", file=sys.stderr)
        sys.exit(1)

    # Parse .env file
    entries = []
    env_pattern = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$')

    with open(env_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            match = env_pattern.match(line)
            if match:
                key = match.group(1)
                value = match.group(2)

                # Remove surrounding quotes
                if (value.startswith('"') and value.endswith('"')) or \
                   (value.startswith("'") and value.endswith("'")):
                    value = value[1:-1]

                entries.append((key, value))

    if not entries:
        print("No entries found in .env file")
        sys.exit(0)

    prefix = args.prefix.rstrip('/')
    migrated = []

    for key, value in entries:
        vault_path_str = f"{prefix}/{key.lower()}"

        if args.dry_run:
            print(f"  Would migrate: {vault_path_str} (from {key})")
            migrated.append(vault_path_str)
        else:
            # Add to vault via daemon
            from .daemon import send_request

            request = {
                "request_id": f"migrate-{key}",
                "action": "add",
                "session_id": session_id,
                "payload": {
                    "path": vault_path_str,
                    "secret": value,
                    "note": f"Migrated from {env_file.name}:{key}",
                    "client_pid": os.getpid()
                }
            }

            response = send_request(request)

            if response.get("status") == "ok":
                migrated.append(vault_path_str)
            else:
                error = response.get("error", {})
                print(f"  Failed to migrate {key}: {error.get('message', 'Unknown error')}", file=sys.stderr)

    if args.dry_run:
        print(f"\nWould migrate {len(migrated)} entries")
    else:
        print(f"Migrated {len(migrated)} entries:")
        for path in migrated:
            print(f"  {path}")

        # Create backup and new .env file
        if len(migrated) > 0:
            backup_file = env_file.with_suffix(env_file.suffix + ".backup")
            new_env_file = env_file.with_suffix(env_file.suffix + ".new")

            # Backup original
            shutil.copy2(env_file, backup_file)
            print(f"\nBackup created: {backup_file}")

            # Create new .env with [CRED:] references
            with open(env_file) as f_in, open(new_env_file, "w") as f_out:
                for line in f_in:
                    stripped = line.strip()
                    if not stripped or stripped.startswith('#'):
                        f_out.write(line)
                        continue

                    match = env_pattern.match(stripped)
                    if match:
                        key = match.group(1)
                        vault_path_str = f"{prefix}/{key.lower()}"
                        if vault_path_str in migrated:
                            f_out.write(f"{key}=[CRED:{vault_path_str}]\n")
                        else:
                            f_out.write(line)
                    else:
                        f_out.write(line)

            print(f"New env file created: {new_env_file}")
            print("\nTo complete migration:")
            print(f"  1. Review {new_env_file}")
            print(f"  2. Replace original: mv {new_env_file} {env_file}")
            print("  3. Use vault-proxy to run commands with credential substitution")


def main():
    parser = argparse.ArgumentParser(
        prog='vault',
        description="Vault CLI - Secure password/secrets manager"
    )
    parser.add_argument(
        '--version',
        action='version',
        version=f"%(prog)s {version('vault-cli')}"
    )
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Global vault option
    parser.add_argument('--vault', help='Path to vault file (default: ~/.vault)')

    # init
    init_parser = subparsers.add_parser('init', help='Create a new vault')
    init_parser.add_argument('--vault', dest='vault', help='Path to vault file')

    # unlock
    unlock_parser = subparsers.add_parser('unlock', help='Unlock vault and create session')
    unlock_parser.add_argument('--ttl', type=int, help='Session TTL in seconds')
    unlock_parser.add_argument('--vault', dest='vault', help='Path to vault file')

    # lock
    lock_parser = subparsers.add_parser('lock', help='Destroy active vault session(s)')
    lock_parser.add_argument('--vault', dest='vault', help='Path to vault file')

    # daemon (v2.0)
    daemon_parser = subparsers.add_parser('daemon', help='Start or stop the vault daemon')
    daemon_parser.add_argument('--foreground', action='store_true', help='Run in foreground')
    daemon_parser.add_argument('--stop', action='store_true', help='Stop running daemon')
    daemon_parser.add_argument('--vault', dest='vault', help='Path to vault file')

    # agent (v2.0)
    agent_parser = subparsers.add_parser('agent', help='Launch command with vault session')
    agent_parser.add_argument('--allow', action='append', help='Allowed path pattern (can specify multiple)')
    agent_parser.add_argument('--ttl', type=int, default=1800, help='Session TTL in seconds (default: 1800)')
    agent_parser.add_argument('--vault', dest='vault', help='Path to vault file')
    agent_parser.add_argument('cmd', nargs=argparse.REMAINDER, help='Command to execute (use -- to separate from flags)')

    # status (v2.0)
    status_parser = subparsers.add_parser('status', help='Show active sessions')
    status_parser.add_argument('--json', action='store_true', help='Output as JSON')

    # revoke (v2.0)
    revoke_parser = subparsers.add_parser('revoke', help='Revoke a specific session')
    revoke_parser.add_argument('session_id', help='Session ID to revoke')

    # add
    add_parser = subparsers.add_parser('add', help='Add or overwrite an entry')
    add_parser.add_argument('path', help='Entry path')
    add_parser.add_argument('--note', help='Optional note')
    add_parser.add_argument('--vault', dest='vault', help='Path to vault file')

    # get
    get_parser = subparsers.add_parser('get', help='Retrieve an entry')
    get_parser.add_argument('path', help='Entry path')
    get_parser.add_argument('--show', action='store_true', help='Print to stdout instead of clipboard')
    get_parser.add_argument('--vault', dest='vault', help='Path to vault file')

    # list
    list_parser = subparsers.add_parser('list', help='List entries')
    list_parser.add_argument('path', nargs='?', help='Prefix path')
    list_parser.add_argument('--vault', dest='vault', help='Path to vault file')

    # delete
    delete_parser = subparsers.add_parser('delete', help='Delete an entry')
    delete_parser.add_argument('path', help='Entry path')
    delete_parser.add_argument('--vault', dest='vault', help='Path to vault file')

    # tree
    tree_parser = subparsers.add_parser('tree', help='Display hierarchical structure')
    tree_parser.add_argument('--vault', dest='vault', help='Path to vault file')

    # mv
    mv_parser = subparsers.add_parser('mv', help='Move/rename an entry')
    mv_parser.add_argument('old_path', help='Current path')
    mv_parser.add_argument('new_path', help='New path')
    mv_parser.add_argument('--vault', dest='vault', help='Path to vault file')

    # search
    search_parser = subparsers.add_parser('search', help='Search entries')
    search_parser.add_argument('term', help='Search term')
    search_parser.add_argument('--vault', dest='vault', help='Path to vault file')

    # proxy
    proxy_parser = subparsers.add_parser('proxy', help='Execute command with credential substitution')
    proxy_parser.add_argument('cmd', nargs=1, help='Command to execute')
    proxy_parser.add_argument('cmd_args', nargs=argparse.REMAINDER, help='Command arguments')
    proxy_parser.add_argument('--vault', dest='vault', help='Path to vault file')

    # migrate-env (v2.0)
    migrate_parser = subparsers.add_parser('migrate-env', help='Migrate .env file to vault')
    migrate_parser.add_argument('env_file', help='Path to .env file')
    migrate_parser.add_argument('--prefix', default='migrated', help='Vault path prefix (default: migrated)')
    migrate_parser.add_argument('--dry-run', action='store_true', help='Show what would be done')
    migrate_parser.add_argument('--vault', dest='vault', help='Path to vault file')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    commands = {
        'init': cmd_init,
        'unlock': cmd_unlock,
        'lock': cmd_lock,
        'daemon': cmd_daemon,
        'agent': cmd_agent,
        'status': cmd_status,
        'revoke': cmd_revoke,
        'add': cmd_add,
        'get': cmd_get,
        'list': cmd_list,
        'delete': cmd_delete,
        'tree': cmd_tree,
        'mv': cmd_mv,
        'search': cmd_search,
        'proxy': cmd_proxy,
        'migrate-env': cmd_migrate_env,
    }

    commands[args.command](args)


if __name__ == '__main__':
    main()
