"""Unit tests for PID tree walker module."""

import os
import sys
import time
from unittest.mock import patch, mock_open

import pytest

from vault_cli.pid_tree import (
    get_pid_tree_linux,
    get_pid_tree_psutil,
    get_pid_tree,
    is_pid_alive,
    get_process_command,
    get_process_start_time,
    is_pid_in_tree,
    get_process_ancestry,
    is_pid_related_to_session,
    clear_cache,
)


class TestPidTreeLinux:
    """Tests for Linux-specific PID tree walking."""

    def test_get_pid_tree_current_process(self):
        """Test getting PID tree for current process."""
        if sys.platform != "linux":
            pytest.skip("Linux-only test")

        current_pid = os.getpid()
        tree = get_pid_tree_linux(current_pid)

        # Current PID should be in the tree
        assert current_pid in tree
        # Should be a set of integers
        assert all(isinstance(pid, int) for pid in tree)

    def test_get_pid_tree_empty_for_dead_pid(self):
        """Test that dead PID returns at least itself or empty."""
        if sys.platform != "linux":
            pytest.skip("Linux-only test")

        # Use a very high PID that's unlikely to exist
        dead_pid = 99999
        tree = get_pid_tree_linux(dead_pid)

        # Should return at least the PID itself even if no children
        assert dead_pid in tree or len(tree) == 0

    def test_get_pid_tree_with_children(self):
        """Test parsing children from /proc - skipped (requires actual process tree)."""
        # This test would require mocking multiple levels of /proc reads
        # The functionality is covered by integration tests
        pytest.skip("Requires complex mocking of recursive /proc reads")

    @patch("builtins.open", side_effect=FileNotFoundError())
    def test_get_pid_tree_file_not_found(self, mock_file):
        """Test handling of missing /proc entry."""
        tree = get_pid_tree_linux(1000)

        # Should return just the root PID
        assert tree == {1000}


class TestPidTreePsutil:
    """Tests for psutil-based PID tree walking."""

    def test_get_pid_tree_psutil_current(self):
        """Test psutil version with current process."""
        pytest.importorskip("psutil")

        current_pid = os.getpid()
        tree = get_pid_tree_psutil(current_pid)

        # Current PID should be in the tree
        assert current_pid in tree

    def test_get_pid_tree_psutil_dead_pid(self):
        """Test psutil version with dead PID."""
        pytest.importorskip("psutil")

        import psutil

        # Use a very high PID that's unlikely to exist
        dead_pid = 99999
        tree = get_pid_tree_psutil(dead_pid)

        # Should return at least the PID
        assert dead_pid in tree


class TestGetPidTree:
    """Tests for the main get_pid_tree function."""

    def test_get_pid_tree_returns_set(self):
        """Test that get_pid_tree returns a set."""
        current_pid = os.getpid()
        tree = get_pid_tree(current_pid, use_cache=False)

        assert isinstance(tree, set)
        assert all(isinstance(pid, int) for pid in tree)

    def test_get_pid_tree_includes_root(self):
        """Test that tree includes the root PID."""
        current_pid = os.getpid()
        tree = get_pid_tree(current_pid, use_cache=False)

        assert current_pid in tree

    def test_get_pid_tree_caching(self):
        """Test that caching works correctly."""
        current_pid = os.getpid()

        # Clear cache first
        clear_cache()

        # First call should populate cache
        tree1 = get_pid_tree(current_pid, use_cache=True)

        # Second call should use cache
        tree2 = get_pid_tree(current_pid, use_cache=True)

        assert tree1 == tree2

        # Non-cached call should still work
        tree3 = get_pid_tree(current_pid, use_cache=False)
        assert tree3 == tree1


class TestIsPidAlive:
    """Tests for PID alive checking."""

    def test_is_pid_alive_current_process(self):
        """Test that current process is alive."""
        current_pid = os.getpid()
        assert is_pid_alive(current_pid) is True

    def test_is_pid_alive_dead_pid(self):
        """Test that non-existent PID is not alive."""
        # Use a very high PID that's unlikely to exist
        dead_pid = 99999
        assert is_pid_alive(dead_pid) is False

    def test_is_pid_alive_zero(self):
        """Test that PID 0 returns False."""
        assert is_pid_alive(0) is False

    def test_is_pid_alive_negative(self):
        """Test that negative PID returns False."""
        assert is_pid_alive(-1) is False


class TestGetProcessCommand:
    """Tests for getting process command names."""

    def test_get_process_command_current(self):
        """Test getting command for current process."""
        current_pid = os.getpid()
        cmd = get_process_command(current_pid)

        # Should return a string (likely "python" or "pytest")
        assert cmd is not None
        assert isinstance(cmd, str)
        assert len(cmd) > 0

    def test_get_process_command_dead_pid(self):
        """Test getting command for dead PID."""
        dead_pid = 99999
        cmd = get_process_command(dead_pid)

        assert cmd is None


class TestGetProcessStartTime:
    """Tests for getting process start time."""

    def test_get_process_start_time_current(self):
        """Test getting start time for current process."""
        if sys.platform != "linux":
            pytest.skip("Linux-specific test")

        current_pid = os.getpid()
        start_time = get_process_start_time(current_pid)

        assert start_time is not None
        assert isinstance(start_time, float)
        # Should be in the past
        assert start_time < time.time()

    def test_get_process_start_time_dead_pid(self):
        """Test getting start time for dead PID."""
        dead_pid = 99999
        start_time = get_process_start_time(dead_pid)

        assert start_time is None


class TestIsPidInTree:
    """Tests for checking PID tree membership."""

    def test_is_pid_in_tree_self(self):
        """Test that a PID is in its own tree."""
        current_pid = os.getpid()

        assert is_pid_in_tree(current_pid, current_pid) is True

    def test_is_pid_in_tree_different_process(self):
        """Test checking different process (likely not in tree)."""
        current_pid = os.getpid()

        # PID 1 (init) is unlikely to be in our tree
        assert is_pid_in_tree(1, current_pid) is False


class TestGetProcessAncestry:
    """Tests for process ancestry discovery."""

    def test_get_process_ancestry_current(self):
        """Test getting ancestry of current process."""
        if sys.platform != "linux":
            pytest.skip("Linux-only test")

        current_pid = os.getpid()
        parent_pid = os.getppid()

        ancestry = get_process_ancestry(current_pid)

        # Parent should be in ancestry
        assert parent_pid in ancestry, f"Parent {parent_pid} should be in ancestry {ancestry}"
        # PID 1 (init) should be in ancestry
        assert 1 in ancestry, f"Init (PID 1) should be in ancestry"

    def test_get_process_ancestry_dead_pid(self):
        """Test getting ancestry of dead PID."""
        if sys.platform != "linux":
            pytest.skip("Linux-only test")

        dead_pid = 99999
        ancestry = get_process_ancestry(dead_pid)

        # Should return empty set for dead PID
        assert ancestry == set()

    def test_get_process_ancestry_not_include_self(self):
        """Test that ancestry doesn't include the input PID."""
        if sys.platform != "linux":
            pytest.skip("Linux-only test")

        current_pid = os.getpid()
        ancestry = get_process_ancestry(current_pid)

        # Ancestry should not include self
        assert current_pid not in ancestry


class TestIsPidRelatedToSession:
    """Tests for PID session relationship checking."""

    def test_is_pid_related_to_session_self(self):
        """Test that a PID is related to its own session."""
        current_pid = os.getpid()

        result = is_pid_related_to_session(current_pid, current_pid)
        assert result is True

    def test_is_pid_related_to_session_parent_child(self):
        """Test parent-child relationship across process groups."""
        current_pid = os.getpid()
        parent_pid = os.getppid()

        # Current process should be related to parent's session
        # (even if in different process groups)
        result = is_pid_related_to_session(current_pid, parent_pid)
        assert result is True, "Child should be related to parent session"

    def test_is_pid_related_to_session_unrelated(self):
        """Test that unrelated PIDs are not related."""
        current_pid = os.getpid()

        # PID 1 (init) is unlikely to be related to current session
        result = is_pid_related_to_session(1, current_pid)
        assert result is False


class TestClearCache:
    """Tests for cache clearing."""

    def test_clear_cache(self):
        """Test that clear_cache doesn't raise errors."""
        # Just verify it doesn't throw
        clear_cache()
