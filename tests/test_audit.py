"""Unit tests for audit logger module."""

import os
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from vault_cli.audit import AuditLogger


class TestAuditLoggerInit:
    """Tests for AuditLogger initialization."""

    def test_init_creates_directory(self, temp_vault_dir):
        """Test that init creates the log directory."""
        log_path = temp_vault_dir / "subdir" / "access.log"
        logger = AuditLogger(log_path)

        assert log_path.parent.exists()
        assert oct(log_path.parent.stat().st_mode)[-3:] == "700"

    def test_init_creates_log_file(self, temp_vault_dir):
        """Test that init creates the log file."""
        log_path = temp_vault_dir / "access.log"
        logger = AuditLogger(log_path)

        assert log_path.exists()
        assert oct(log_path.stat().st_mode)[-3:] == "600"

    def test_init_existing_log_file(self, temp_vault_dir):
        """Test init with existing log file."""
        log_path = temp_vault_dir / "access.log"
        log_path.write_text("existing content\n")

        logger = AuditLogger(log_path)

        assert log_path.exists()
        # Content should be preserved
        assert "existing content" in log_path.read_text()


class TestLogAccess:
    """Tests for log_access method."""

    def test_log_access_format(self, audit_logger):
        """Test correct log line format."""
        audit_logger.log_access(
            pid=12345,
            command="claude",
            result="ALLOWED",
            action="GET",
            path="work/api/key"
        )

        recent = audit_logger.read_recent(1)
        assert len(recent) == 1

        parts = recent[0].strip().split()
        # Format: TIMESTAMP [PID/command] RESULT ACTION path
        assert len(parts) >= 5
        assert parts[2] == "ALLOWED"
        assert parts[3] == "GET"
        assert parts[4] == "work/api/key"
        assert "[12345/claude]" in recent[0]

    def test_log_access_with_reason(self, audit_logger):
        """Test log line with reason field."""
        audit_logger.log_access(
            pid=12345,
            command="claude",
            result="DENIED",
            action="GET",
            path="personal/bank",
            reason="out-of-scope"
        )

        recent = audit_logger.read_recent(1)
        assert "out-of-scope" in recent[0]

    def test_log_access_timestamp_format(self, audit_logger):
        """Test ISO8601 timestamp format."""
        audit_logger.log_access(
            pid=12345,
            command="test",
            result="ALLOWED",
            action="GET",
            path="test"
        )

        recent = audit_logger.read_recent(1)
        line = recent[0]

        # Should start with timestamp like 2025-02-15T10:23:01.123456Z
        timestamp_part = line.split()[0]
        assert timestamp_part.endswith("Z")
        assert "T" in timestamp_part

    def test_log_access_all_results(self, audit_logger):
        """Test all result types."""
        results = ["ALLOWED", "DENIED", "EXPIRED", "REVOKED", "ERROR"]

        for result in results:
            audit_logger.log_access(
                pid=12345,
                command="test",
                result=result,
                action="GET",
                path="test"
            )

        recent = audit_logger.read_recent(len(results))
        logged_results = [line.split()[2] for line in recent]

        for result in results:
            assert result in logged_results

    def test_log_access_thread_safety(self, audit_logger):
        """Test thread-safe logging."""
        import threading

        errors = []

        def log_entries():
            try:
                for i in range(10):
                    audit_logger.log_access(
                        pid=12345,
                        command="test",
                        result="ALLOWED",
                        action="GET",
                        path=f"test/{i}"
                    )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=log_entries) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        recent = audit_logger.read_recent(100)
        assert len(recent) == 50


class TestLogRotation:
    """Tests for log rotation."""

    def test_rotation_creates_new_file(self, audit_logger):
        """Test rotation creates new log file."""
        # Write some content
        audit_logger.log_access(
            pid=12345, command="test", result="ALLOWED", action="GET", path="test"
        )

        # Manually trigger rotation
        audit_logger._rotate()

        # Should have created rotated file
        rotated_files = list(audit_logger.log_path.parent.glob("access.log.*"))
        assert len(rotated_files) == 1

    def test_rotation_preserves_content(self, audit_logger):
        """Test that rotation preserves old content."""
        audit_logger.log_access(
            pid=12345, command="test", result="ALLOWED", action="GET", path="old_entry"
        )

        # Force rotation
        audit_logger._rotate()

        # Find rotated file
        rotated = list(audit_logger.log_path.parent.glob("access.log.*"))[0]
        assert "old_entry" in rotated.read_text()

    def test_rotation_not_needed_same_day(self, audit_logger):
        """Test no rotation when file is from today."""
        audit_logger.log_access(
            pid=12345, command="test", result="ALLOWED", action="GET", path="test"
        )

        # Don't modify mtime - it's today
        audit_logger._check_rotation()

        rotated = list(audit_logger.log_path.parent.glob("access.log.*"))
        assert len(rotated) == 0


class TestLogCleanup:
    """Tests for old log cleanup."""

    def test_cleanup_removes_old_logs(self, temp_vault_dir):
        """Test that old rotated logs are removed."""
        log_path = temp_vault_dir / "access.log"
        logger = AuditLogger(log_path, retention_days=7)

        # Create old rotated logs
        old_date = datetime.now(timezone.utc) - timedelta(days=10)
        old_filename = f"access.log.{old_date.strftime('%Y%m%d')}"
        old_log = temp_vault_dir / old_filename
        old_log.write_text("old content")

        # Create recent rotated log
        recent_date = datetime.now(timezone.utc) - timedelta(days=2)
        recent_filename = f"access.log.{recent_date.strftime('%Y%m%d')}"
        recent_log = temp_vault_dir / recent_filename
        recent_log.write_text("recent content")

        # Trigger cleanup
        logger._cleanup_old_logs()

        assert not old_log.exists()
        assert recent_log.exists()

    def test_cleanup_keeps_current_log(self, audit_logger):
        """Test that current log is not removed."""
        audit_logger.log_access(
            pid=12345, command="test", result="ALLOWED", action="GET", path="test"
        )

        audit_logger._cleanup_old_logs()

        assert audit_logger.log_path.exists()


class TestReadRecent:
    """Tests for reading recent log entries."""

    def test_read_recent_returns_lines(self, audit_logger):
        """Test reading recent entries."""
        for i in range(5):
            audit_logger.log_access(
                pid=12345, command="test", result="ALLOWED", action="GET", path=f"test/{i}"
            )

        recent = audit_logger.read_recent(3)

        assert len(recent) == 3
        # Should be last 3 entries
        assert "test/2" in recent[0]
        assert "test/4" in recent[-1]

    def test_read_recent_empty_log(self, audit_logger):
        """Test reading from empty log."""
        recent = audit_logger.read_recent(10)

        assert recent == []

    def test_read_recent_more_than_available(self, audit_logger):
        """Test reading more lines than exist."""
        audit_logger.log_access(
            pid=12345, command="test", result="ALLOWED", action="GET", path="test"
        )

        recent = audit_logger.read_recent(100)

        assert len(recent) == 1

    def test_read_recent_file_not_exist(self, temp_vault_dir):
        """Test reading when log file doesn't exist."""
        log_path = temp_vault_dir / "nonexistent" / "access.log"
        logger = AuditLogger(log_path)

        # Remove the file that was created
        if log_path.exists():
            log_path.unlink()

        recent = logger.read_recent(10)

        assert recent == []


class TestGetLogFiles:
    """Tests for getting all log files."""

    def test_get_log_files_sorted(self, audit_logger):
        """Test that log files are sorted by time."""
        # Create current log
        audit_logger.log_access(
            pid=12345, command="test", result="ALLOWED", action="GET", path="test"
        )

        # Create rotated logs with different times
        for i in range(3):
            date = datetime.now(timezone.utc) - timedelta(days=i + 1)
            filename = f"access.log.{date.strftime('%Y%m%d')}"
            log_file = audit_logger.log_path.parent / filename
            log_file.write_text(f"content {i}")
            # Set modification time
            mtime = time.time() - (i + 1) * 86400
            os.utime(log_file, (mtime, mtime))

        logs = audit_logger.get_log_files()

        assert len(logs) == 4  # 1 current + 3 rotated
        # Should be sorted newest first
        assert logs[0].name == "access.log"
