# Vault CLI

[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

A minimal, secure, hierarchical password and secrets manager with **PID-bound sessions for AI agent security**.

**Key Features:**
- 🔐 **Strong cryptography**: Argon2id + XSalsa20-Poly1305 (via libsodium/PyNaCl)
- 🌳 **Hierarchical organization**: Store secrets at paths like `work/aws/prod` or `personal/email/gmail`
- 🤖 **PID-bound sessions**: AI agents get scoped access tied to their process—no credential leakage
- 👁️ **Real-time monitoring**: All access logged to `~/.vault/access.log` for instant visibility
- 🔑 **Credential proxy**: Execute commands with `[CRED:path]` pattern substitution
- 📋 **Clipboard integration**: Secrets copied securely, never touch shell history
- 🏠 **Self-contained**: Single SQLite file, no external services

---

## Table of Contents

- [Why Vault CLI?](#why-vault-cli)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [PID-Bound Sessions (v2.0)](#pid-bound-sessions-v20)
- [Usage Guide](#usage-guide)
- [Vault-Proxy Mode](#vault-proxy-mode)
- [Security](#security)
- [Comparison](#comparison)
- [Contributing](#contributing)
- [License](#license)

---

## Why Vault CLI?

AI agents (Claude Code, Cursor, Copilot) create a new credential security problem:

- **Agents read `.env` files by default**, exposing secrets in chat history
- **Traditional password managers** require interactive auth per access—unsuitable for agents
- **No existing tool provides real-time visibility** into what credentials AI agents access

Vault CLI solves this with **PID-bound sessions**:

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   vault agent   │────▶│   Vault Daemon   │────▶│   ~/.vault/     │
│   (launcher)    │     │   (key holder)   │     │   (SQLite DB)   │
└────────┬────────┘     └────────┬─────────┘     └─────────────────┘
         │                       │
         │ launches              │
         ▼                       │
┌─────────────────┐              │         ┌──────────────────┐
│  Claude/Code    │──────────────┘         │  ~/.vault/       │
│  (AI agent)     │    Unix socket         │  access.log      │
└─────────────────┘                       └──────────────────┘
```

| Feature | Vault CLI | Pass | 1Password CLI | HashiCorp Vault |
|---------|-----------|------|---------------|-----------------|
| No server required | ✅ | ✅ | ❌ | ❌ |
| PID-bound sessions | ✅ | ❌ | ❌ | ❌ |
| Real-time audit log | ✅ | ❌ | ❌ | ✅ |
| Scoped agent access | ✅ | ❌ | ❌ | ✅ |
| Credential proxy | ✅ | ❌ | ❌ | ❌ |
| Open source | ✅ | ✅ | ❌ | ✅ |

---

## Installation

### From GitHub (Recommended)

Install directly from the repository using `uv`:

```bash
uv tool install git+https://github.com/user/vault-cli.git
```

Or using `pip`:

```bash
pip install git+https://github.com/user/vault-cli.git
```

### From Source (Development)

```bash
git clone https://github.com/user/vault-cli.git
cd vault-cli
uv sync
```

Then use `uv run` for all commands:

```bash
# Run vault
uv run vault --version

# Run tests
uv run pytest

# Run linting
uv run ruff check .
```

### PyPI (Coming Soon)

Once published:

```bash
uv tool install vault-cli
# or
pip install vault-cli
```

---

## Quick Start

```bash
# 1. Create a new vault (one-time setup)
vault init
Enter master password: ********
Confirm master password: ********
Vault created at ~/.vault

# 2. Start the daemon
vault daemon
Vault daemon started (PID: 2345)

# 3. Launch Claude with scoped access
vault agent --allow "work/*" --ttl 3600 -- claude
Enter master password: ********
[Claude launches with access to work/* only]

# 4. Inside Claude, retrieve secrets
vault get work/api/key
(copied to clipboard)

# 5. Claude CANNOT access personal secrets
vault get personal/bank
Error: Access denied: path 'personal/bank' not in session scope

# 6. Monitor in real-time (another terminal)
tail -f ~/.vault/access.log
2025-02-15T10:23:01Z [12345/claude] ALLOWED GET work/api/key
2025-02-15T10:24:15Z [12345/claude] DENIED GET personal/bank out-of-scope

# 7. Emergency lock (revokes all sessions)
vault lock
Locked: 1 session revoked

# Lock a specific vault
vault lock --vault /path/to/custom.vault
```

---

## PID-Bound Sessions (v2.0)

### The Problem

AI agents need credential access, but traditional approaches are insecure:

| Approach | Problem |
|----------|---------|
| `.env` files | Agents leak secrets in chat history |
| Unlocked password manager | No visibility, no scope control |
| Interactive unlock per access | Doesn't work for autonomous agents |

### The Solution: PID-Bound Sessions

Sessions are **bound to a process tree**, not just a time window:

1. **Process Authentication**: Only the launched process and its children can access vault
2. **Scope Control**: Each session has explicit path patterns (e.g., `work/*`)
3. **Real-time Logging**: Every access attempt logged immediately
4. **Auto-Revoke**: Session dies when process dies or TTL expires

### Commands

#### vault daemon

Start or stop the vault daemon:

```bash
# Start daemon in background
vault daemon
Vault daemon started (PID: 2345)

# Run in foreground (for debugging)
vault daemon --foreground

# Stop daemon
vault daemon --stop
Vault daemon stopped
```

#### vault agent

Launch a command with a vault session:

```bash
# Launch Claude with work scope (flags before command)
vault agent --allow "work/*" --ttl 3600 claude

# Or use -- separator for clarity (recommended)
vault agent --allow "work/*" --ttl 3600 -- claude

# Multiple scopes
vault agent --allow "work/*" --allow "personal/email/*" --ttl 7200 -- claude

# Launch any command
vault agent --allow "production/*" --ttl 600 -- python deploy.py

# Create session without launching (sets VAULT_SESSION_ID)
vault agent --allow "work/*" --ttl 3600
Session created: vs-a3f9k2m8
Expires in 3600 seconds
Set VAULT_SESSION_ID environment variable to use:
  export VAULT_SESSION_ID=vs-a3f9k2m8
```

**Options:**
- `--allow <pattern>`: Allowed path pattern (can specify multiple)
- `--ttl <seconds>`: Session TTL (default: 1800)
- `--vault <path>`: Use custom vault path
- `-- <command>`: Use `--` to separate vault options from the command being launched

#### vault status

Show active sessions:

```bash
vault status
Vault: UNLOCKED (2 active sessions)

Session: vs-a3f9k2m8
  PID: 12345 (claude)
  Scope: work/*
  Expires: 32 mins
  Accesses: 12 allowed, 1 denied

Session: vs-b7d4m1p9
  PID: 12389 (python deploy.py)
  Scope: work/*, personal/email/*
  Expires: 58 mins
  Accesses: 3 allowed, 0 denied

# JSON output for scripting
vault status --json
```

#### vault revoke

Revoke a specific session:

```bash
vault revoke vs-a3f9k2m8
Session vs-a3f9k2m8 revoked
```

#### vault lock

Revoke all sessions (emergency lock):

```bash
vault lock
Locked: 2 sessions revoked
```

### Audit Logging

All access is logged to `~/.vault/access.log`:

```
2025-02-15T10:23:01.123456Z [12345/claude] ALLOWED GET work/api/key
2025-02-15T10:24:15.789012Z [12345/claude] DENIED GET personal/bank out-of-scope
2025-02-15T10:30:00.000000Z [12345/claude] EXPIRED SESSION vs-a3f9k2m8 ttl-expired
2025-02-15T10:31:45.456789Z [12389/python] ALLOWED PROXY work/db psql
```

**Log format:**
- `timestamp`: ISO8601 with microseconds (UTC)
- `[PID/command]`: Process ID and command name
- `result`: ALLOWED | DENIED | EXPIRED | REVOKED | ERROR
- `action`: GET | ADD | DELETE | LIST | PROXY | SESSION
- `path`: Vault path or session ID
- `reason`: Optional (for DENIED/ERROR)

**Rotation:**
- Daily rotation at midnight UTC
- Current: `~/.vault/access.log`
- Rotated: `~/.vault/access.log.YYYYMMDD`
- Retention: 30 days

### Migration from .env

Migrate existing `.env` files to vault:

```bash
# Create session for migration
vault agent bash --allow "work/project/*" --ttl 600

# Migrate
vault migrate-env .env.local --prefix "work/project"
Migrated 5 entries:
  work/project/database_url
  work/project/api_key
  work/project/secret_key
  work/project/aws_access_key
  work/project/aws_secret_key

# Dry run to preview
vault migrate-env .env.local --prefix "work/project" --dry-run
Would migrate 5 entries:
  work/project/database_url (from DATABASE_URL)
  ...
```

---

## Usage Guide

### Vault Management

| Command | Description |
|---------|-------------|
| `vault init [--vault PATH]` | Create a new vault (default: `~/.vault`) |
| `vault daemon [--foreground] [--stop]` | Start/stop the vault daemon |
| `vault unlock [--ttl SECONDS]` | Unlock vault (use `VAULT_PASSWORD` env var for automation) |
| `vault lock [--vault PATH]` | Revoke all sessions |
| `vault --version` | Show version information |
| `vault status [--json]` | Show active sessions |
| `vault revoke <session_id>` | Revoke specific session |

### Secret Operations

| Command | Description |
|---------|-------------|
| `vault add <path> [--note TEXT]` | Add or overwrite an entry |
| `vault get <path> [--show]` | Retrieve entry (clipboard or stdout) |
| `vault list [path]` | List entries (optionally under prefix) |
| `vault tree` | Display hierarchical tree view |
| `vault search <term>` | Case-insensitive substring search |
| `vault mv <old> <new>` | Move or rename an entry |
| `vault delete <path>` | Delete an entry |
| `vault migrate-env <file> [--prefix P] [--dry-run]` | Migrate .env to vault |

### Examples

```bash
# Organize hierarchically
vault add personal/banking/chase --note "Chase Sapphire"
vault add work/github/token --note "GitHub PAT"
vault add work/aws/prod/access_key

# Search across all entries
vault search aws
# work/aws/dev/access_key
# work/aws/prod/access_key

# List only work entries
vault list work
```

---

## Vault-Proxy Mode

Execute commands with credential substitution:

```bash
# Start daemon and create session
vault daemon
vault agent bash --allow "db/*" --ttl 3600

# Use credentials in commands
vault-proxy psql postgresql://[CRED:db_prod_user]:[CRED:db_prod_pass]@host/db
vault-proxy curl -H "Authorization: Bearer [CRED:api_token]" https://api.example.com
vault-proxy ansible-playbook -e "db_pass=[CRED:db_password]" deploy.yml

# Use with custom vault path
vault-proxy --vault /path/to/work.vault psql postgresql://[CRED:user]:[CRED:pass]@host/db
```

**How it works:**
1. `[CRED:path]` patterns matched against vault entries
2. Credentials substituted at execution time
3. Scripts contain only references, never actual secrets
4. Uses same vault as `vault` command (respects `--vault` option)

---

## Security

### Cryptographic Design

| Component | Implementation |
|-----------|----------------|
| Key Derivation | Argon2id (OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE) |
| Encryption | XSalsa20-Poly1305 (NaCl SecretBox) |
| Salt | 16 bytes random per vault |
| Nonce | 24 bytes random per entry |
| Key | 32 bytes derived from master password |

### PID-Bound Session Security

| Threat | Protection |
|--------|------------|
| Session ID leaked | Useless without matching PID tree |
| Process impersonation | PID validated against session tree |
| PID reuse | Start time checked to detect reuse |
| Session hijacking | Session dies with originating process |
| Scope bypass | Path matched against explicit patterns |

### General Security

| Threat | Protection |
|--------|------------|
| Vault file stolen | Encrypted, needs master password |
| Password in shell history | `getpass` prevents echo |
| Process snooping | Credentials in memory only during use |
| Tampering | Authenticated encryption (Poly1305) |
| Daemon crash recovery | Auto-detects and cleans stale socket/PID files |

### Automation & Environment Variables

For automation and CI/CD pipelines, you can provide the master password via environment variable:

```bash
# Use VAULT_PASSWORD for non-interactive unlock
export VAULT_PASSWORD="your-master-password"
vault unlock
vault get work/api/key

# Or one-shot
VAULT_PASSWORD="$(cat /run/secrets/vault_pass)" vault agent ci-script.sh --allow "prod/*"
```

**Security Warning:** Environment variables may be visible in process lists (`ps e`). For production, use file-based secrets or secret management systems that inject via `/run/secrets/`.

### Version Information

```bash
# Check installed version
vault --version
vault 2.0.0
```

### File Locations

| File | Location | Permissions |
|------|----------|-------------|
| Vault database | `~/.vault` | 0o600 |
| Daemon socket | `~/.vault/daemon.sock` | 0o600 |
| Daemon PID | `~/.vault/daemon.pid` | 0o600 |
| Audit log | `~/.vault/access.log` | 0o600 |
| Legacy session | `~/.vault-session` | 0o600 |

---

## Comparison

### vs `pass` (Password Store)

| | Vault CLI | pass |
|--|-----------|------|
| Storage | SQLite | GPG-encrypted files |
| PID-bound sessions | ✅ | ❌ |
| Real-time audit | ✅ | ❌ |
| Credential proxy | ✅ | ❌ |
| Git integration | Manual | Built-in |

### vs 1Password CLI

| | Vault CLI | 1Password CLI |
|--|-----------|---------------|
| Cost | Free | Subscription |
| Offline | ✅ | Partial |
| PID scoping | ✅ | ❌ |
| Biometric unlock | ❌ | ✅ |

### vs HashiCorp Vault

| | Vault CLI | HashiCorp Vault |
|--|-----------|-----------------|
| Server | None | Required |
| PID sessions | ✅ | ❌ |
| Complexity | Minimal | Significant |
| Dynamic secrets | ❌ | ✅ |

---

## Contributing

Contributions welcome! Please submit a Pull Request.

### Development Setup

```bash
git clone https://github.com/user/vault-cli.git
cd vault-cli
uv sync
```

### Running Tests

```bash
uv run pytest
```

### Code Quality

```bash
uv run ruff check .
uv run ruff format .
uv run mypy src/
```

### Project Structure

```
vault-cli/
├── src/vault_cli/
│   ├── __init__.py
│   ├── main.py          # Main CLI implementation
│   ├── daemon.py        # Background daemon
│   ├── session.py       # Session management
│   ├── protocol.py      # Socket protocol
│   ├── pid_tree.py      # Process tree discovery
│   ├── audit.py         # Audit logging
│   └── vault_proxy.py   # Proxy entry point
├── tests/
├── pyproject.toml
└── README.md
```

---

## License

MIT License - see [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- [PyNaCl](https://github.com/pyca/pynacl/) for Python bindings to libsodium
- [Argon2](https://github.com/P-H-C/phc-winner-argon2) for the memory-hard KDF
- [psutil](https://github.com/giampaolo/psutil) for cross-platform process utilities
- Inspired by [`pass`](https://www.passwordstore.org/) and [HashiCorp Vault](https://www.vaultproject.io/)
