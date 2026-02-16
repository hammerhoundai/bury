"""Tests for vault_proxy credential substitution."""

import re
import sys
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vault_cli.vault_proxy import main


class TestCredentialPatternMatching:
    """Tests for credential pattern matching."""

    def test_cred_pattern_simple(self):
        """Test simple CRED pattern matching."""
        pattern = re.compile(r"\[CRED:([^\]]+)\]")
        match = pattern.search("Value is [CRED:test/key]")
        assert match is not None
        assert match.group(1) == "test/key"

    def test_cred_pattern_nested_path(self):
        """Test CRED pattern with nested path."""
        pattern = re.compile(r"\[CRED:([^\]]+)\]")
        match = pattern.search("Value is [CRED:prod/db/password]")
        assert match is not None
        assert match.group(1) == "prod/db/password"

    def test_cred_pattern_multiple(self):
        """Test multiple CRED patterns in one string."""
        pattern = re.compile(r"\[CRED:([^\]]+)\]")
        text = "First: [CRED:a/b], Second: [CRED:c/d]"
        matches = pattern.findall(text)
        assert len(matches) == 2
        assert "a/b" in matches
        assert "c/d" in matches

    def test_cred_pattern_no_match(self):
        """Test CRED pattern with no match."""
        pattern = re.compile(r"\[CRED:([^\]]+)\]")
        match = pattern.search("No credentials here")
        assert match is None

    def test_cred_pattern_empty_brackets(self):
        """Test CRED pattern with empty brackets - should not match."""
        pattern = re.compile(r"\[CRED:([^\]]+)\]")
        match = pattern.search("Value is [CRED:]")
        # Empty brackets don't match because [^\]]+ requires at least one char
        assert match is None

    def test_cred_pattern_special_chars(self):
        """Test CRED pattern with special characters in path."""
        pattern = re.compile(r"\[CRED:([^\]]+)\]")
        match = pattern.search("Value is [CRED:test-key_123]")
        assert match is not None
        assert match.group(1) == "test-key_123"


class TestVaultProxyMain:
    """Tests for vault_proxy main function."""

    @patch("vault_cli.vault_proxy.get_vault_path")
    @patch("vault_cli.vault_proxy.get_key_or_unlock")
    @patch("vault_cli.vault_proxy.sqlite3")
    @patch("vault_cli.vault_proxy.os.execvp")
    def test_main_no_command(self, mock_execvp, mock_sqlite3, mock_get_key, mock_get_vault):
        """Test main with no command."""
        mock_get_vault.return_value = Path("/tmp/test.vault")

        with patch.object(sys, "argv", ["vault-proxy"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 2

    @patch("vault_cli.vault_proxy.get_vault_path")
    @patch("vault_cli.vault_proxy.get_key_or_unlock")
    @patch("vault_cli.vault_proxy.sqlite3")
    @patch("vault_cli.vault_proxy.os.execvp")
    def test_main_vault_not_found(self, mock_execvp, mock_sqlite3, mock_get_key, mock_get_vault):
        """Test main when vault doesn't exist."""
        mock_get_vault.return_value = Path("/tmp/nonexistent.vault")

        with patch.object(sys, "argv", ["vault-proxy", "echo", "test"]):
            with patch("vault_cli.vault_proxy.Path.exists", return_value=False):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 1

    @patch("vault_cli.vault_proxy.get_vault_path")
    @patch("vault_cli.vault_proxy.get_key_or_unlock")
    @patch("vault_cli.vault_proxy.sqlite3")
    @patch("vault_cli.vault_proxy.decrypt_secret")
    @patch("vault_cli.vault_proxy.os.execvp")
    def test_main_simple_substitution(
        self, mock_execvp, mock_decrypt, mock_sqlite3, mock_get_key, mock_get_vault
    ):
        """Test main with simple credential substitution."""
        mock_get_vault.return_value = Path("/tmp/test.vault")
        mock_get_key.return_value = b"key" * 8
        mock_decrypt.return_value = '{"secret": "mysecretvalue"}'

        mock_conn = MagicMock()
        mock_conn.cursor.return_value.fetchall.return_value = [
            ("test/key", b"ciphertext", b"nonce"),
        ]
        mock_sqlite3.connect.return_value = mock_conn

        with patch.object(sys, "argv", ["vault-proxy", "echo", "[CRED:test/key]"]):
            with patch("vault_cli.vault_proxy.Path.exists", return_value=True):
                main()

        mock_execvp.assert_called_once()
        args = mock_execvp.call_args[0][1]
        assert "mysecretvalue" in args

    @patch("vault_cli.vault_proxy.get_vault_path")
    @patch("vault_cli.vault_proxy.get_key_or_unlock")
    @patch("vault_cli.vault_proxy.sqlite3")
    @patch("vault_cli.vault_proxy.decrypt_secret")
    @patch("vault_cli.vault_proxy.os.execvp")
    def test_main_multiple_substitutions(
        self, mock_execvp, mock_decrypt, mock_sqlite3, mock_get_key, mock_get_vault
    ):
        """Test main with multiple credential substitutions."""
        mock_get_vault.return_value = Path("/tmp/test.vault")
        mock_get_key.return_value = b"key" * 8

        def decrypt_side_effect(key, ciphertext, nonce):
            if ciphertext == b"cipher1":
                return '{"secret": "value1"}'
            elif ciphertext == b"cipher2":
                return '{"secret": "value2"}'
            return '{"secret": "unknown"}'

        mock_decrypt.side_effect = decrypt_side_effect

        mock_conn = MagicMock()
        mock_conn.cursor.return_value.fetchall.return_value = [
            ("test/key1", b"cipher1", b"nonce1"),
            ("test/key2", b"cipher2", b"nonce2"),
        ]
        mock_sqlite3.connect.return_value = mock_conn

        with patch.object(sys, "argv", ["vault-proxy", "echo", "[CRED:test/key1] [CRED:test/key2]"]):
            with patch("vault_cli.vault_proxy.Path.exists", return_value=True):
                main()

        mock_execvp.assert_called_once()
        args = mock_execvp.call_args[0][1]
        assert "value1" in args[1]
        assert "value2" in args[1]

    @patch("vault_cli.vault_proxy.get_vault_path")
    @patch("vault_cli.vault_proxy.get_key_or_unlock")
    @patch("vault_cli.vault_proxy.sqlite3")
    @patch("vault_cli.vault_proxy.decrypt_secret")
    @patch("vault_cli.vault_proxy.os.execvp")
    def test_main_missing_credential(
        self, mock_execvp, mock_decrypt, mock_sqlite3, mock_get_key, mock_get_vault
    ):
        """Test main when credential not found (should keep original pattern)."""
        mock_get_vault.return_value = Path("/tmp/test.vault")
        mock_get_key.return_value = b"key" * 8
        mock_decrypt.return_value = '{"secret": "found"}'

        mock_conn = MagicMock()
        mock_conn.cursor.return_value.fetchall.return_value = [
            ("test/exists", b"ciphertext", b"nonce"),
        ]
        mock_sqlite3.connect.return_value = mock_conn

        with patch.object(sys, "argv", ["vault-proxy", "echo", "[CRED:test/missing]"]):
            with patch("vault_cli.vault_proxy.Path.exists", return_value=True):
                main()

        mock_execvp.assert_called_once()
        args = mock_execvp.call_args[0][1]
        assert "[CRED:test/missing]" in args

    @patch("vault_cli.vault_proxy.get_vault_path")
    @patch("vault_cli.vault_proxy.get_key_or_unlock")
    @patch("vault_cli.vault_proxy.sqlite3")
    @patch("vault_cli.vault_proxy.os.execvp")
    def test_main_custom_vault_arg(
        self, mock_execvp, mock_sqlite3, mock_get_key, mock_get_vault
    ):
        """Test main with --vault argument."""
        mock_get_vault.return_value = Path("/custom/path.vault")
        mock_get_key.return_value = b"key" * 8

        mock_conn = MagicMock()
        mock_conn.cursor.return_value.fetchall.return_value = []
        mock_sqlite3.connect.return_value = mock_conn

        with patch.object(sys, "argv", ["vault-proxy", "--vault", "/custom/path.vault", "echo", "test"]):
            with patch("vault_cli.vault_proxy.Path.exists", return_value=True):
                main()

        mock_get_vault.assert_called_once()

    @patch("vault_cli.vault_proxy.get_vault_path")
    @patch("vault_cli.vault_proxy.get_key_or_unlock")
    @patch("vault_cli.vault_proxy.sqlite3")
    @patch("vault_cli.vault_proxy.os.execvp")
    def test_main_vault_equals_syntax(
        self, mock_execvp, mock_sqlite3, mock_get_key, mock_get_vault
    ):
        """Test main with --vault=/path syntax."""
        mock_get_vault.return_value = Path("/custom/path.vault")
        mock_get_key.return_value = b"key" * 8

        mock_conn = MagicMock()
        mock_conn.cursor.return_value.fetchall.return_value = []
        mock_sqlite3.connect.return_value = mock_conn

        with patch.object(sys, "argv", ["vault-proxy", "--vault=/custom/path.vault", "echo", "test"]):
            with patch("vault_cli.vault_proxy.Path.exists", return_value=True):
                main()

        mock_get_vault.assert_called_once()

    @patch("vault_cli.vault_proxy.get_vault_path")
    @patch("vault_cli.vault_proxy.get_key_or_unlock")
    @patch("vault_cli.vault_proxy.sqlite3")
    @patch("vault_cli.vault_proxy.decrypt_secret")
    @patch("vault_cli.vault_proxy.os.execvp")
    def test_main_complex_command(
        self, mock_execvp, mock_decrypt, mock_sqlite3, mock_get_key, mock_get_vault
    ):
        """Test main with complex command having multiple arguments."""
        mock_get_vault.return_value = Path("/tmp/test.vault")
        mock_get_key.return_value = b"key" * 8
        mock_decrypt.return_value = '{"secret": "secretpass"}'

        mock_conn = MagicMock()
        mock_conn.cursor.return_value.fetchall.return_value = [
            ("db/password", b"ciphertext", b"nonce"),
        ]
        mock_sqlite3.connect.return_value = mock_conn

        with patch.object(sys, "argv", [
            "vault-proxy",
            "python", "script.py",
            "--db-pass", "[CRED:db/password]",
            "--verbose"
        ]):
            with patch("vault_cli.vault_proxy.Path.exists", return_value=True):
                main()

        mock_execvp.assert_called_once()
        cmd, args = mock_execvp.call_args[0]
        assert cmd == "python"
        assert args[0] == "python"
        assert args[1] == "script.py"
        assert "secretpass" in args[3]
        assert args[4] == "--verbose"

    @patch("vault_cli.vault_proxy.get_vault_path")
    @patch("vault_cli.vault_proxy.get_key_or_unlock")
    @patch("vault_cli.vault_proxy.sqlite3")
    @patch("vault_cli.vault_proxy.os.execvp")
    def test_main_no_credentials_in_args(
        self, mock_execvp, mock_sqlite3, mock_get_key, mock_get_vault
    ):
        """Test main when no credentials in arguments."""
        mock_get_vault.return_value = Path("/tmp/test.vault")
        mock_get_key.return_value = b"key" * 8

        mock_conn = MagicMock()
        mock_conn.cursor.return_value.fetchall.return_value = []
        mock_sqlite3.connect.return_value = mock_conn

        with patch.object(sys, "argv", ["vault-proxy", "echo", "hello world"]):
            with patch("vault_cli.vault_proxy.Path.exists", return_value=True):
                main()

        mock_execvp.assert_called_once()
        args = mock_execvp.call_args[0][1]
        assert args == ["echo", "hello world"]


class TestVaultProxyEdgeCases:
    """Tests for edge cases in vault_proxy."""

    @patch("vault_cli.vault_proxy.get_vault_path")
    @patch("vault_cli.vault_proxy.get_key_or_unlock")
    @patch("vault_cli.vault_proxy.sqlite3")
    @patch("vault_cli.vault_proxy.decrypt_secret")
    @patch("vault_cli.vault_proxy.os.execvp")
    def test_decrypt_failure_handled(
        self, mock_execvp, mock_decrypt, mock_sqlite3, mock_get_key, mock_get_vault
    ):
        """Test that decrypt failures are handled gracefully."""
        mock_get_vault.return_value = Path("/tmp/test.vault")
        mock_get_key.return_value = b"key" * 8
        mock_decrypt.side_effect = Exception("Decrypt failed")

        mock_conn = MagicMock()
        mock_conn.cursor.return_value.fetchall.return_value = [
            ("test/key", b"ciphertext", b"nonce"),
        ]
        mock_sqlite3.connect.return_value = mock_conn

        with patch.object(sys, "argv", ["vault-proxy", "echo", "[CRED:test/key]"]):
            with patch("vault_cli.vault_proxy.Path.exists", return_value=True):
                main()

        mock_execvp.assert_called_once()

    @patch("vault_cli.vault_proxy.get_vault_path")
    @patch("vault_cli.vault_proxy.get_key_or_unlock")
    @patch("vault_cli.vault_proxy.sqlite3")
    @patch("vault_cli.vault_proxy.os.execvp")
    def test_empty_vault(
        self, mock_execvp, mock_sqlite3, mock_get_key, mock_get_vault
    ):
        """Test with empty vault (no entries)."""
        mock_get_vault.return_value = Path("/tmp/test.vault")
        mock_get_key.return_value = b"key" * 8

        mock_conn = MagicMock()
        mock_conn.cursor.return_value.fetchall.return_value = []
        mock_sqlite3.connect.return_value = mock_conn

        with patch.object(sys, "argv", ["vault-proxy", "echo", "test"]):
            with patch("vault_cli.vault_proxy.Path.exists", return_value=True):
                main()

        mock_execvp.assert_called_once()
        args = mock_execvp.call_args[0][1]
        assert args == ["echo", "test"]
