#!/usr/bin/env python3
"""Vault Proxy - Standalone credential substitution proxy.

Executes commands with [CRED:path] pattern substitution from vault secrets.

Example:
    vault-proxy echo "secret is [CRED:test/key]"
    vault-proxy --vault /custom.vault echo "secret is [CRED:test/key]"
"""

import argparse
import json
import os
import re
import sqlite3
import sys
from pathlib import Path

from .main import (
    DEFAULT_VAULT,
    decrypt_secret,
    get_key_or_unlock,
    get_vault_path,
)


def main():
    """Execute command with credential substitution."""
    # Pre-parse to extract --vault before argparse.REMAINDER consumes it
    vault_path = None
    argv = sys.argv[1:]

    i = 0
    while i < len(argv):
        if argv[i] == "--vault" and i + 1 < len(argv):
            vault_path = argv[i + 1]
            argv = argv[:i] + argv[i + 2:]
            break
        elif argv[i].startswith("--vault="):
            vault_path = argv[i].split("=", 1)[1]
            argv = argv[:i] + argv[i + 1:]
            break
        i += 1

    parser = argparse.ArgumentParser(
        description="Execute commands with vault credential substitution",
        usage="vault-proxy [--vault PATH] <command> [args...]",
    )
    parser.add_argument(
        "cmd",
        nargs=argparse.REMAINDER,
        help="Command and arguments to execute",
    )

    args = parser.parse_args(argv)

    if not args.cmd:
        parser.error("No command specified")

    vault_path = get_vault_path(vault_path)

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
            credentials[path] = data["secret"]
        except Exception:
            pass

    # Substitute [CRED:path] patterns in arguments
    pattern = re.compile(r"\[CRED:([^\]]+)\]")

    new_args = []
    for arg in args.cmd:
        new_arg = pattern.sub(lambda m: credentials.get(m.group(1), m.group(0)), arg)
        new_args.append(new_arg)

    # Execute command
    os.execvp(new_args[0], new_args)


if __name__ == "__main__":
    main()
