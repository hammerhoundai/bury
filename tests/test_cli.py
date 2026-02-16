"""Tests for CLI commands and argument parsing."""

import argparse
import json
import os
import sys
from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock, mock_open, patch

import pytest

# Import the main module
from vault_cli.main import (
    cmd_add,
    cmd_delete,
    cmd_get,
    cmd_init,
    cmd_list,
    cmd_lock,
    cmd_migrate_env,
    cmd_mv,
    cmd_search,
    cmd_tree,
    cmd_unlock,
    copy_to_clipboard,
    decrypt_secret,
    derive_key,
    encrypt_secret,
    get_key_or_unlock,
    get_password,
    get_vault_path,
    load_session,
    main,
    set_permissions,
)
from vault_cli.daemon import send_request, ping_daemon


class TestGetPassword:
    """Tests for get_password helper function."""

    def test_get_password_from_env(self):
        """Test that VAULT_PASSWORD env var is used when set."""
        with patch.dict(os.environ, {"VAULT_PASSWORD": "testpass123"}):
            result = get_password()
            assert result == "testpass123"

    def test_get_password_from_env_custom_prompt(self):
        """Test that VAULT_PASSWORD works with custom prompt."""
        with patch.dict(os.environ, {"VAULT_PASSWORD": "testpass456"}):
            result = get_password("Custom prompt: ")
            assert result == "testpass456"

    @patch("vault_cli.main.getpass.getpass")
    def test_get_password_fallback_to_getpass(self, mock_getpass):
        """Test fallback to getpass when env var not set."""
        mock_getpass.return_value = "manualpass"
        with patch.dict(os.environ, {}, clear=True):
            result = get_password("Enter password: ")
            assert result == "manualpass"
            mock_getpass.assert_called_once_with("Enter password: ")

    @patch("vault_cli.main.getpass.getpass")
    def test_get_password_empty_env_uses_getpass(self, mock_getpass):
        """Test that empty env var falls back to getpass."""
        mock_getpass.return_value = "manualpass"
        with patch.dict(os.environ, {"VAULT_PASSWORD": ""}):
            result = get_password()
            assert result == "manualpass"


class TestGetVaultPath:
    """Tests for get_vault_path function."""

    def test_get_vault_path_with_arg(self):
        """Test vault path from argument."""
        result = get_vault_path("/custom/path.vault")
        assert result == Path("/custom/path.vault")

    def test_get_vault_path_default(self):
        """Test default vault path."""
        result = get_vault_path(None)
        assert result == Path.home() / ".vault"

    def test_get_vault_path_no_arg(self):
        """Test vault path with no argument."""
        result = get_vault_path()
        assert result == Path.home() / ".vault"


class TestSetPermissions:
    """Tests for set_permissions function."""

    @patch("vault_cli.main.os.chmod")
    def test_set_permissions_default(self, mock_chmod):
        """Test default permissions (0o600)."""
        set_permissions("/path/to/file")
        mock_chmod.assert_called_once_with("/path/to/file", 0o600)

    @patch("vault_cli.main.os.chmod")
    def test_set_permissions_custom(self, mock_chmod):
        """Test custom permissions."""
        set_permissions("/path/to/file", 0o700)
        mock_chmod.assert_called_once_with("/path/to/file", 0o700)


class TestLoadSession:
    """Tests for load_session function."""

    @patch("vault_cli.main.SESSION_FILE")
    @patch("vault_cli.main.datetime")
    def test_load_session_valid(self, mock_datetime, mock_session_file):
        """Test loading a valid session."""
        mock_session_file.exists.return_value = True

        session_data = {
            "key": "dGVzdGtleQ==",
            "expires": "2099-01-01T00:00:00+00:00"
        }

        mock_file = mock_open(read_data=json.dumps(session_data))
        with patch("builtins.open", mock_file):
            mock_now = MagicMock()
            mock_now.__gt__ = MagicMock(return_value=False)
            mock_datetime.now.return_value = mock_now
            mock_datetime.fromisoformat.return_value = mock_now

            result = load_session()
            assert result is not None

    @patch("vault_cli.main.SESSION_FILE")
    def test_load_session_no_file(self, mock_session_file):
        """Test loading when session file doesn't exist."""
        mock_session_file.exists.return_value = False
        result = load_session()
        assert result is None

    @patch("vault_cli.main.SESSION_FILE")
    def test_load_session_invalid_json(self, mock_session_file):
        """Test loading with invalid JSON."""
        mock_session_file.exists.return_value = True
        mock_file = mock_open(read_data="invalid json")

        with patch("builtins.open", mock_file):
            result = load_session()
            assert result is None
            assert mock_session_file.unlink.called


class TestCopyToClipboard:
    """Tests for copy_to_clipboard function."""

    @patch("vault_cli.main.subprocess.run")
    @patch("vault_cli.main.os.path.exists")
    @patch("builtins.open", mock_open(read_data="Linux version"))
    def test_copy_to_clipboard_linux(self, mock_exists, mock_run):
        """Test clipboard on Linux."""
        mock_exists.return_value = True
        mock_run.return_value = MagicMock(returncode=0)

        copy_to_clipboard("secret text")
        mock_run.assert_called_once()


class TestCmdInit:
    """Tests for cmd_init function."""

    @patch("vault_cli.main.set_permissions")
    @patch("vault_cli.main.get_password")
    @patch("vault_cli.main.nacl.utils.random")
    @patch("vault_cli.main.init_db")
    @patch("vault_cli.main.derive_key")
    @patch("vault_cli.main.encrypt_secret")
    @patch("vault_cli.main.sqlite3")
    def test_cmd_init_success(
        self, mock_sqlite3, mock_encrypt, mock_derive,
        mock_init_db, mock_random, mock_get_password, mock_set_perm
    ):
        """Test successful vault initialization."""
        mock_get_password.side_effect = ["password", "password"]
        mock_random.return_value = b"salt" * 4
        mock_derive.return_value = b"key" * 8
        mock_encrypt.return_value = (b"ciphertext", b"nonce")

        mock_conn = MagicMock()
        mock_sqlite3.connect.return_value = mock_conn

        args = argparse.Namespace(vault="/tmp/test.vault")

        with patch("vault_cli.main.Path.exists", return_value=False):
            with patch("vault_cli.main.get_vault_path", return_value=Path("/tmp/test.vault")):
                cmd_init(args)

    @patch("vault_cli.main.get_password")
    def test_cmd_init_password_mismatch(self, mock_get_password):
        """Test init with password mismatch."""
        mock_get_password.side_effect = ["password1", "password2"]

        args = argparse.Namespace(vault="/tmp/test.vault")

        with patch("vault_cli.main.Path.exists", return_value=False):
            with patch("vault_cli.main.get_vault_path", return_value=Path("/tmp/test.vault")):
                with pytest.raises(SystemExit):
                    cmd_init(args)

    def test_cmd_init_vault_exists(self):
        """Test init when vault already exists."""
        args = argparse.Namespace(vault="/tmp/test.vault")

        with patch("vault_cli.main.Path.exists", return_value=True):
            with patch("vault_cli.main.get_vault_path", return_value=Path("/tmp/test.vault")):
                with pytest.raises(SystemExit):
                    cmd_init(args)


class TestCmdUnlock:
    """Tests for cmd_unlock function."""

    @patch("vault_cli.main.get_password")
    @patch("vault_cli.main.unlock_vault")
    @patch("vault_cli.main.set_permissions")
    @patch("builtins.open", mock_open())
    def test_cmd_unlock_success(self, mock_set_perm, mock_unlock, mock_get_password):
        """Test successful unlock."""
        mock_get_password.return_value = "password"
        mock_unlock.return_value = b"key" * 8

        args = argparse.Namespace(vault="/tmp/test.vault", ttl=1800)

        with patch("vault_cli.main.get_vault_path", return_value=Path("/tmp/test.vault")):
            cmd_unlock(args)


class TestCmdLock:
    """Tests for cmd_lock function."""

    @patch("vault_cli.daemon.ping_daemon")
    @patch("vault_cli.daemon.send_request")
    def test_cmd_lock_with_daemon(self, mock_send_request, mock_ping):
        """Test lock with daemon running."""
        mock_ping.return_value = True
        mock_send_request.side_effect = [
            {
                "status": "ok",
                "data": {
                    "sessions": [
                        {"session_id": "session1"},
                        {"session_id": "session2"}
                    ]
                }
            },
            {"status": "ok"},
            {"status": "ok"},
        ]

        args = argparse.Namespace(vault=None)

        with patch("vault_cli.main.get_vault_path", return_value=Path("/tmp/test.vault")):
            cmd_lock(args)


class TestCmdGet:
    """Tests for cmd_get function."""

    @patch("vault_cli.main.os.environ.get")
    @patch("vault_cli.daemon.send_request")
    def test_cmd_get_with_session(self, mock_send_request, mock_env_get):
        """Test get with active session."""
        mock_env_get.return_value = "session123"
        mock_send_request.return_value = {
            "status": "ok",
            "data": {"secret": "mysecret", "note": ""}
        }

        args = argparse.Namespace(path="test/key", show=True, vault=None)

        with patch("vault_cli.main.Path.exists", return_value=True):
            with patch("vault_cli.main.get_vault_path", return_value=Path("/tmp/test.vault")):
                with patch("vault_cli.main.copy_to_clipboard"):
                    cmd_get(args)


class TestCmdList:
    """Tests for cmd_list function."""

    @patch("vault_cli.main.sqlite3")
    def test_cmd_list_all(self, mock_sqlite3):
        """Test listing all entries."""
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.fetchall.return_value = [
            ("test/key1",),
            ("test/key2",),
        ]
        mock_sqlite3.connect.return_value = mock_conn

        args = argparse.Namespace(path=None, vault=None)

        with patch("vault_cli.main.Path.exists", return_value=True):
            with patch("vault_cli.main.get_vault_path", return_value=Path("/tmp/test.vault")):
                cmd_list(args)


class TestCmdDelete:
    """Tests for cmd_delete function."""

    @patch("vault_cli.main.sqlite3")
    def test_cmd_delete_success(self, mock_sqlite3):
        """Test successful delete."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = (1,)
        mock_conn.cursor.return_value = mock_cursor
        mock_sqlite3.connect.return_value = mock_conn

        args = argparse.Namespace(path="test/key", vault=None)

        with patch("vault_cli.main.Path.exists", return_value=True):
            with patch("vault_cli.main.get_vault_path", return_value=Path("/tmp/test.vault")):
                cmd_delete(args)

        # Verify the delete operations
        mock_cursor.execute.assert_any_call("SELECT 1 FROM entries WHERE path = ?", ("test/key",))
        mock_cursor.execute.assert_any_call("DELETE FROM entries WHERE path = ?", ("test/key",))
        mock_conn.commit.assert_called_once()

    @patch("vault_cli.main.sqlite3")
    def test_cmd_delete_nonexistent_path(self, mock_sqlite3, capsys):
        """Test delete non-existent path."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = None
        mock_conn.cursor.return_value = mock_cursor
        mock_sqlite3.connect.return_value = mock_conn

        args = argparse.Namespace(path="nonexistent/key", vault=None)

        with patch("vault_cli.main.Path.exists", return_value=True):
            with patch("vault_cli.main.get_vault_path", return_value=Path("/tmp/test.vault")):
                with pytest.raises(SystemExit) as exc_info:
                    cmd_delete(args)
                assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Entry not found: nonexistent/key" in captured.err

    def test_cmd_delete_vault_not_found(self):
        """Test delete when vault file doesn't exist."""
        args = argparse.Namespace(path="test/key", vault="/nonexistent.vault")

        with patch("vault_cli.main.Path.exists", return_value=False):
            with patch("vault_cli.main.get_vault_path", return_value=Path("/nonexistent.vault")):
                with pytest.raises(SystemExit) as exc_info:
                    cmd_delete(args)
                assert exc_info.value.code == 1

    @patch("vault_cli.main.sqlite3")
    def test_cmd_delete_custom_vault_path(self, mock_sqlite3):
        """Test delete with custom vault path."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = (1,)
        mock_conn.cursor.return_value = mock_cursor
        mock_sqlite3.connect.return_value = mock_conn

        args = argparse.Namespace(path="test/key", vault="/custom/path.vault")

        with patch("vault_cli.main.Path.exists", return_value=True):
            with patch("vault_cli.main.get_vault_path", return_value=Path("/custom/path.vault")):
                cmd_delete(args)

        # Verify correct vault path was used
        mock_sqlite3.connect.assert_called_once_with(Path("/custom/path.vault"))


class TestCmdTree:
    """Tests for cmd_tree function."""

    @patch("vault_cli.main.sqlite3")
    def test_cmd_tree_nested_paths(self, mock_sqlite3, capsys):
        """Test tree display with nested paths like work/aws/prod/key."""
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.fetchall.return_value = [
            ("work/aws/prod/key",),
            ("work/aws/dev/key",),
            ("personal/bank/chase",),
        ]
        mock_sqlite3.connect.return_value = mock_conn

        args = argparse.Namespace(vault=None)

        with patch("vault_cli.main.Path.exists", return_value=True):
            with patch("vault_cli.main.get_vault_path", return_value=Path("/tmp/test.vault")):
                cmd_tree(args)

        captured = capsys.readouterr()
        # Verify tree structure shows proper nesting
        assert "work" in captured.out
        assert "aws" in captured.out
        assert "prod" in captured.out
        assert "dev" in captured.out
        assert "personal" in captured.out
        assert "bank" in captured.out
        assert "chase" in captured.out
        # Verify tree connectors are present
        assert "├──" in captured.out or "└──" in captured.out

    @patch("vault_cli.main.sqlite3")
    def test_cmd_tree_single_level(self, mock_sqlite3, capsys):
        """Test tree display with single level entries."""
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.fetchall.return_value = [
            ("key1",),
            ("key2",),
            ("key3",),
        ]
        mock_sqlite3.connect.return_value = mock_conn

        args = argparse.Namespace(vault=None)

        with patch("vault_cli.main.Path.exists", return_value=True):
            with patch("vault_cli.main.get_vault_path", return_value=Path("/tmp/test.vault")):
                cmd_tree(args)

        captured = capsys.readouterr()
        # Verify flat structure
        assert "key1" in captured.out
        assert "key2" in captured.out
        assert "key3" in captured.out
        # Should have tree connectors even at top level
        assert "├──" in captured.out or "└──" in captured.out

    @patch("vault_cli.main.sqlite3")
    def test_cmd_tree_empty_vault(self, mock_sqlite3, capsys):
        """Test tree display with empty vault."""
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.fetchall.return_value = []
        mock_sqlite3.connect.return_value = mock_conn

        args = argparse.Namespace(vault=None)

        with patch("vault_cli.main.Path.exists", return_value=True):
            with patch("vault_cli.main.get_vault_path", return_value=Path("/tmp/test.vault")):
                cmd_tree(args)

        captured = capsys.readouterr()
        # Empty vault should produce no output
        assert captured.out == ""

    @patch("vault_cli.main.sqlite3")
    def test_cmd_tree_mixed_depths(self, mock_sqlite3, capsys):
        """Test tree with entries at different depths."""
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.fetchall.return_value = [
            ("root",),
            ("a/b",),
            ("a/c/d",),
        ]
        mock_sqlite3.connect.return_value = mock_conn

        args = argparse.Namespace(vault=None)

        with patch("vault_cli.main.Path.exists", return_value=True):
            with patch("vault_cli.main.get_vault_path", return_value=Path("/tmp/test.vault")):
                cmd_tree(args)

        captured = capsys.readouterr()
        # Verify all entries appear
        assert "root" in captured.out
        assert "a" in captured.out
        assert "b" in captured.out
        assert "c" in captured.out
        assert "d" in captured.out

    @patch("vault_cli.main.sqlite3")
    def test_cmd_tree_with_vault_path(self, mock_sqlite3, capsys):
        """Test tree with custom vault path."""
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.fetchall.return_value = [
            ("test/key",),
        ]
        mock_sqlite3.connect.return_value = mock_conn

        args = argparse.Namespace(vault="/custom/path.vault")

        with patch("vault_cli.main.Path.exists", return_value=True):
            with patch("vault_cli.main.get_vault_path", return_value=Path("/custom/path.vault")):
                cmd_tree(args)

        captured = capsys.readouterr()
        assert "test" in captured.out
        assert "key" in captured.out
        # Verify correct vault path was used
        mock_sqlite3.connect.assert_called_once_with(Path("/custom/path.vault"))

    def test_cmd_tree_vault_not_found(self):
        """Test tree when vault file doesn't exist."""
        args = argparse.Namespace(vault="/nonexistent.vault")

        with patch("vault_cli.main.Path.exists", return_value=False):
            with patch("vault_cli.main.get_vault_path", return_value=Path("/nonexistent.vault")):
                with pytest.raises(SystemExit) as exc_info:
                    cmd_tree(args)
                assert exc_info.value.code == 1


class TestCmdMv:
    """Tests for cmd_mv function."""

    @patch("vault_cli.main.sqlite3")
    def test_cmd_mv_success(self, mock_sqlite3):
        """Test successful move from old path to new path."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.side_effect = [
            ("2024-01-01T00:00:00", b"ciphertext", b"nonce"),
            None,
        ]
        mock_conn.cursor.return_value = mock_cursor
        mock_sqlite3.connect.return_value = mock_conn

        args = argparse.Namespace(old_path="old/key", new_path="new/key", vault=None)

        with patch("vault_cli.main.Path.exists", return_value=True):
            with patch("vault_cli.main.get_vault_path", return_value=Path("/tmp/test.vault")):
                cmd_mv(args)

        # Verify the move operations
        mock_cursor.execute.assert_any_call("SELECT created, ciphertext, nonce FROM entries WHERE path = ?", ("old/key",))
        mock_cursor.execute.assert_any_call("SELECT 1 FROM entries WHERE path = ?", ("new/key",))
        mock_cursor.execute.assert_any_call(
            "INSERT INTO entries (path, ciphertext, nonce, created, modified) VALUES (?, ?, ?, ?, ?)",
            ("new/key", b"ciphertext", b"nonce", "2024-01-01T00:00:00", mock.ANY)
        )
        mock_cursor.execute.assert_any_call("DELETE FROM entries WHERE path = ?", ("old/key",))
        mock_conn.commit.assert_called_once()

    @patch("vault_cli.main.sqlite3")
    def test_cmd_mv_nonexistent_source(self, mock_sqlite3, capsys):
        """Test move non-existent source (should error)."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = None
        mock_conn.cursor.return_value = mock_cursor
        mock_sqlite3.connect.return_value = mock_conn

        args = argparse.Namespace(old_path="nonexistent/key", new_path="new/key", vault=None)

        with patch("vault_cli.main.Path.exists", return_value=True):
            with patch("vault_cli.main.get_vault_path", return_value=Path("/tmp/test.vault")):
                with pytest.raises(SystemExit) as exc_info:
                    cmd_mv(args)
                assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Entry not found: nonexistent/key" in captured.err

    @patch("vault_cli.main.sqlite3")
    def test_cmd_mv_existing_destination(self, mock_sqlite3, capsys):
        """Test move to existing destination (should error)."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.side_effect = [
            ("2024-01-01T00:00:00", b"ciphertext", b"nonce"),
            (1,),  # Destination exists
        ]
        mock_conn.cursor.return_value = mock_cursor
        mock_sqlite3.connect.return_value = mock_conn

        args = argparse.Namespace(old_path="old/key", new_path="existing/key", vault=None)

        with patch("vault_cli.main.Path.exists", return_value=True):
            with patch("vault_cli.main.get_vault_path", return_value=Path("/tmp/test.vault")):
                with pytest.raises(SystemExit) as exc_info:
                    cmd_mv(args)
                assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Entry already exists: existing/key" in captured.err

    def test_cmd_mv_vault_not_found(self):
        """Test move when vault file doesn't exist."""
        args = argparse.Namespace(old_path="old/key", new_path="new/key", vault="/nonexistent.vault")

        with patch("vault_cli.main.Path.exists", return_value=False):
            with patch("vault_cli.main.get_vault_path", return_value=Path("/nonexistent.vault")):
                with pytest.raises(SystemExit) as exc_info:
                    cmd_mv(args)
                assert exc_info.value.code == 1


class TestCmdSearch:
    """Tests for cmd_search function."""

    @patch("vault_cli.main.sqlite3")
    def test_cmd_search_found(self, mock_sqlite3, capsys):
        """Test search finding matches in paths."""
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.fetchall.return_value = [
            ("test/secret",),
            ("test/password",),
            ("other/key",),
        ]
        mock_sqlite3.connect.return_value = mock_conn

        args = argparse.Namespace(term="pass", vault=None)

        with patch("vault_cli.main.Path.exists", return_value=True):
            with patch("vault_cli.main.get_vault_path", return_value=Path("/tmp/test.vault")):
                cmd_search(args)

        captured = capsys.readouterr()
        assert "test/password" in captured.out
        assert "test/secret" not in captured.out
        assert "other/key" not in captured.out

    @patch("vault_cli.main.sqlite3")
    def test_cmd_search_no_matches(self, mock_sqlite3, capsys):
        """Test search with no matches."""
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.fetchall.return_value = [
            ("test/secret",),
            ("other/key",),
        ]
        mock_sqlite3.connect.return_value = mock_conn

        args = argparse.Namespace(term="nonexistent", vault=None)

        with patch("vault_cli.main.Path.exists", return_value=True):
            with patch("vault_cli.main.get_vault_path", return_value=Path("/tmp/test.vault")):
                cmd_search(args)

        captured = capsys.readouterr()
        assert captured.out == ""

    @patch("vault_cli.main.sqlite3")
    def test_cmd_search_case_insensitive(self, mock_sqlite3, capsys):
        """Test case-insensitive search."""
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.fetchall.return_value = [
            ("test/Password",),
            ("test/SECRET",),
            ("other/key",),
        ]
        mock_sqlite3.connect.return_value = mock_conn

        args = argparse.Namespace(term="pass", vault=None)

        with patch("vault_cli.main.Path.exists", return_value=True):
            with patch("vault_cli.main.get_vault_path", return_value=Path("/tmp/test.vault")):
                cmd_search(args)

        captured = capsys.readouterr()
        assert "test/Password" in captured.out

        # Test uppercase search term
        args = argparse.Namespace(term="SECRET", vault=None)

        with patch("vault_cli.main.Path.exists", return_value=True):
            with patch("vault_cli.main.get_vault_path", return_value=Path("/tmp/test.vault")):
                cmd_search(args)

        captured = capsys.readouterr()
        assert "test/SECRET" in captured.out

    @patch("vault_cli.main.sqlite3")
    def test_cmd_search_multiple_matches(self, mock_sqlite3, capsys):
        """Test search finding multiple matches."""
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.fetchall.return_value = [
            ("prod/db/password",),
            ("dev/db/password",),
            ("staging/api/password",),
            ("other/key",),
        ]
        mock_sqlite3.connect.return_value = mock_conn

        args = argparse.Namespace(term="password", vault=None)

        with patch("vault_cli.main.Path.exists", return_value=True):
            with patch("vault_cli.main.get_vault_path", return_value=Path("/tmp/test.vault")):
                cmd_search(args)

        captured = capsys.readouterr()
        assert "prod/db/password" in captured.out
        assert "dev/db/password" in captured.out
        assert "staging/api/password" in captured.out
        assert "other/key" not in captured.out

    def test_cmd_search_vault_not_found(self):
        """Test search when vault file doesn't exist."""
        args = argparse.Namespace(term="test", vault="/nonexistent.vault")

        with patch("vault_cli.main.Path.exists", return_value=False):
            with patch("vault_cli.main.get_vault_path", return_value=Path("/nonexistent.vault")):
                with pytest.raises(SystemExit) as exc_info:
                    cmd_search(args)
                assert exc_info.value.code == 1


class TestCmdMigrateEnv:
    """Tests for cmd_migrate_env function."""

    @patch.dict(os.environ, {"VAULT_SESSION_ID": "test-session-123"})
    @patch("vault_cli.main.get_vault_path")
    @patch("vault_cli.main.Path.exists")
    @patch("builtins.open", mock_open(read_data="DB_PASSWORD=secret123\nAPI_KEY=abc456\n"))
    def test_cmd_migrate_env_dry_run(self, mock_exists, mock_get_vault_path, capsys):
        """Test dry-run mode (shows what would migrate)."""
        mock_exists.return_value = True
        mock_get_vault_path.return_value = Path("/tmp/test.vault")

        args = argparse.Namespace(env_file="/tmp/.env", prefix="migrated", dry_run=True, vault=None)

        cmd_migrate_env(args)

        captured = capsys.readouterr()
        assert "Would migrate" in captured.out
        assert "migrated/db_password" in captured.out
        assert "migrated/api_key" in captured.out

    @patch.dict(os.environ, {"VAULT_SESSION_ID": "test-session-123"})
    @patch("shutil.copy2")
    @patch("vault_cli.main.get_vault_path")
    @patch("vault_cli.main.Path.exists")
    @patch("vault_cli.daemon.send_request")
    @patch("builtins.open", mock_open(read_data="DB_PASSWORD=secret123\n"))
    def test_cmd_migrate_env_actual_migration(self, mock_send_request, mock_exists, mock_get_vault_path, mock_copy2, capsys):
        """Test actual migration."""
        mock_exists.return_value = True
        mock_get_vault_path.return_value = Path("/tmp/test.vault")
        mock_send_request.return_value = {"status": "ok"}

        args = argparse.Namespace(env_file="/tmp/.env", prefix="migrated", dry_run=False, vault=None)

        cmd_migrate_env(args)

        captured = capsys.readouterr()
        assert "Migrated 1 entries" in captured.out
        assert "migrated/db_password" in captured.out

        # Verify send_request was called with correct data
        mock_send_request.assert_called_once()
        call_args = mock_send_request.call_args[0][0]
        assert call_args["action"] == "add"
        assert call_args["session_id"] == "test-session-123"
        assert call_args["payload"]["path"] == "migrated/db_password"
        assert call_args["payload"]["secret"] == "secret123"

    @patch.dict(os.environ, {"VAULT_SESSION_ID": "test-session-123"})
    @patch("vault_cli.main.get_vault_path")
    @patch("vault_cli.main.Path.exists")
    def test_cmd_migrate_env_missing_file(self, mock_exists, mock_get_vault_path, capsys):
        """Test with missing file (error)."""
        mock_exists.return_value = False
        mock_get_vault_path.return_value = Path("/tmp/test.vault")

        args = argparse.Namespace(env_file="/nonexistent/.env", prefix="migrated", dry_run=True, vault=None)

        with pytest.raises(SystemExit) as exc_info:
            cmd_migrate_env(args)
        assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Env file not found" in captured.err

    @patch.dict(os.environ, {"VAULT_SESSION_ID": "test-session-123"})
    @patch("vault_cli.main.get_vault_path")
    @patch("vault_cli.main.Path.exists")
    @patch("builtins.open", mock_open(read_data="DB_PASSWORD=secret123\nAPI_KEY=abc456\n"))
    def test_cmd_migrate_env_prefix_option(self, mock_exists, mock_get_vault_path, capsys):
        """Test prefix option (adds prefix to all keys)."""
        mock_exists.return_value = True
        mock_get_vault_path.return_value = Path("/tmp/test.vault")

        args = argparse.Namespace(env_file="/tmp/.env", prefix="prod/app", dry_run=True, vault=None)

        cmd_migrate_env(args)

        captured = capsys.readouterr()
        assert "prod/app/db_password" in captured.out
        assert "prod/app/api_key" in captured.out

    @patch.dict(os.environ, {}, clear=True)
    @patch("vault_cli.main.get_vault_path")
    @patch("vault_cli.main.Path.exists")
    def test_cmd_migrate_env_no_session(self, mock_exists, mock_get_vault_path, capsys):
        """Test with no active session."""
        mock_exists.return_value = True
        mock_get_vault_path.return_value = Path("/tmp/test.vault")

        args = argparse.Namespace(env_file="/tmp/.env", prefix="migrated", dry_run=False, vault=None)

        with pytest.raises(SystemExit) as exc_info:
            cmd_migrate_env(args)
        assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "No active session" in captured.err

    @patch.dict(os.environ, {"VAULT_SESSION_ID": "test-session-123"})
    @patch("vault_cli.main.get_vault_path")
    @patch("vault_cli.main.Path.exists")
    @patch("builtins.open", mock_open(read_data="# Comment line\nDB_PASSWORD=secret123\n\nAPI_KEY='quoted_value'\n"))
    def test_cmd_migrate_env_skips_comments_and_empty(self, mock_exists, mock_get_vault_path, capsys):
        """Test that comments and empty lines are skipped."""
        mock_exists.return_value = True
        mock_get_vault_path.return_value = Path("/tmp/test.vault")

        args = argparse.Namespace(env_file="/tmp/.env", prefix="migrated", dry_run=True, vault=None)

        cmd_migrate_env(args)

        captured = capsys.readouterr()
        # Comments should not appear
        assert "# Comment" not in captured.out
        # Empty lines should be handled
        assert "migrated/db_password" in captured.out
        assert "migrated/api_key" in captured.out

    @patch.dict(os.environ, {"VAULT_SESSION_ID": "test-session-123"})
    @patch("vault_cli.main.get_vault_path")
    @patch("vault_cli.main.Path.exists")
    @patch("vault_cli.daemon.send_request")
    @patch("builtins.open", mock_open(read_data="DB_PASSWORD=secret123\n"))
    def test_cmd_migrate_env_failed_migration(self, mock_send_request, mock_exists, mock_get_vault_path, capsys):
        """Test handling of failed migration."""
        mock_exists.return_value = True
        mock_get_vault_path.return_value = Path("/tmp/test.vault")
        mock_send_request.return_value = {"status": "error", "error": {"message": "Access denied"}}

        args = argparse.Namespace(env_file="/tmp/.env", prefix="migrated", dry_run=False, vault=None)

        cmd_migrate_env(args)

        captured = capsys.readouterr()
        assert "Failed to migrate" in captured.err
        assert "Migrated 0 entries" in captured.out


class TestMainArgumentParsing:
    """Tests for main() argument parsing."""

    @patch("vault_cli.main.cmd_init")
    def test_main_init_command(self, mock_cmd_init):
        """Test main with init command."""
        with patch.object(sys, "argv", ["vault", "init"]):
            main()
        mock_cmd_init.assert_called_once()

    @patch("vault_cli.main.cmd_get")
    def test_main_get_command(self, mock_cmd_get):
        """Test main with get command."""
        with patch.object(sys, "argv", ["vault", "get", "test/key"]):
            main()
        mock_cmd_get.assert_called_once()

    @patch("vault_cli.main.cmd_list")
    def test_main_list_command(self, mock_cmd_list):
        """Test main with list command."""
        with patch.object(sys, "argv", ["vault", "list"]):
            main()
        mock_cmd_list.assert_called_once()

    def test_main_no_command(self):
        """Test main with no command."""
        with patch.object(sys, "argv", ["vault"]):
            with pytest.raises(SystemExit):
                main()
