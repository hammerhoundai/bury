#!/usr/bin/env python3
"""Audit Logger - Tamper-evident access logging for vault operations.

Provides append-only logging with daily rotation and retention management.
"""

import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional


class AuditLogger:
    """Append-only audit logger with rotation and retention."""

    def __init__(self, log_path: Path, retention_days: int = 30):
        """Initialize audit logger.

        Args:
            log_path: Path to the log file (e.g., ~/.vault/access.log)
            retention_days: Number of days to keep rotated logs

        """
        self.log_path = Path(log_path)
        self.retention_days = retention_days
        self.lock = threading.Lock()
        self._last_rotation_check: Optional[datetime] = None

        # Ensure parent directory exists
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path.parent.chmod(0o700)

        # Create log file with secure permissions if it doesn't exist
        if not self.log_path.exists():
            fd = os.open(
                str(self.log_path),
                os.O_CREAT | os.O_APPEND | os.O_WRONLY,
                0o600
            )
            os.close(fd)

    def log_access(
        self,
        pid: int,
        command: str,
        result: str,
        action: str,
        path: str,
        reason: Optional[str] = None
    ) -> None:
        """Log an access attempt.

        Format: ISO8601Z [PID/command] RESULT ACTION path [reason]

        Args:
            pid: Process ID
            command: Command name
            result: ALLOWED | DENIED | EXPIRED | REVOKED | ERROR
            action: GET | ADD | DELETE | LIST | CREATE_SESSION | etc.
            path: Vault path or session ID
            reason: Optional reason for DENIED/ERROR

        """
        # Check for rotation
        self._check_rotation()

        # Format timestamp
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        # Format log line
        parts = [
            timestamp,
            f"[{pid}/{command}]",
            result,
            action,
            path
        ]

        if reason:
            parts.append(reason)

        log_line = " ".join(parts) + "\n"

        # Write atomically
        with self.lock, open(self.log_path, "a") as f:
            f.write(log_line)

    def _check_rotation(self) -> None:
        """Check if daily rotation is needed."""
        now = datetime.now(timezone.utc)

        # Only check once per hour at most
        if self._last_rotation_check:
            if (now - self._last_rotation_check).total_seconds() < 3600:
                return

        self._last_rotation_check = now

        # Check if log file exists and was modified on a different day
        if not self.log_path.exists():
            return

        try:
            mtime = datetime.fromtimestamp(
                self.log_path.stat().st_mtime,
                tz=timezone.utc
            )

            # If modified before today (UTC midnight), rotate
            today_midnight = now.replace(
                hour=0, minute=0, second=0, microsecond=0
            )

            if mtime < today_midnight:
                self._rotate()
                self._cleanup_old_logs()

        except OSError:
            pass

    def _rotate(self) -> None:
        """Rotate the current log file."""
        if not self.log_path.exists():
            return

        # Get yesterday's date for the rotated filename
        yesterday = datetime.now(timezone.utc) - timedelta(days=1)
        rotated_name = f"access.log.{yesterday.strftime('%Y%m%d')}"
        rotated_path = self.log_path.parent / rotated_name

        # Only rotate if the target doesn't already exist
        if not rotated_path.exists():
            try:
                self.log_path.rename(rotated_path)
            except OSError:
                pass

    def _cleanup_old_logs(self) -> None:
        """Remove logs older than retention period."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.retention_days)

        try:
            for log_file in self.log_path.parent.glob("access.log.*"):
                try:
                    # Extract date from filename
                    date_str = log_file.name.split(".")[-1]
                    log_date = datetime.strptime(date_str, "%Y%m%d").replace(
                        tzinfo=timezone.utc
                    )

                    if log_date < cutoff:
                        log_file.unlink()
                except (ValueError, OSError):
                    # Invalid filename or deletion error, skip
                    pass
        except OSError:
            pass

    def read_recent(self, lines: int = 100) -> list:
        """Read recent log entries.

        Args:
            lines: Maximum number of lines to read

        Returns:
            List of log lines (most recent last)

        """
        if not self.log_path.exists():
            return []

        try:
            with open(self.log_path) as f:
                all_lines = f.readlines()
                return all_lines[-lines:]
        except OSError:
            return []

    def get_log_files(self) -> list:
        """Get list of all log files (current and rotated).

        Returns:
            List of Path objects, sorted newest first

        """
        logs = []

        if self.log_path.exists():
            logs.append(self.log_path)

        try:
            for log_file in self.log_path.parent.glob("access.log.*"):
                logs.append(log_file)
        except OSError:
            pass

        # Sort by modification time, newest first
        logs.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        return logs
