#!/usr/bin/env python3
"""PID Tree Walker - Cross-platform process tree discovery for authentication.

Provides functionality to discover all PIDs in a process tree, enabling
PID-bound session authentication.
"""

import os
import sys
import time
from functools import lru_cache
from typing import Optional, Set


def get_pid_tree_linux(pid: int) -> Set[int]:
    """Get all PIDs in process tree starting from pid (Linux implementation).

    Uses /proc/<pid>/task/<pid>/children to discover child processes.
    """
    pids = {pid}

    try:
        children_file = f"/proc/{pid}/task/{pid}/children"
        with open(children_file) as f:
            children = f.read().strip().split()

        for child in children:
            try:
                child_pid = int(child)
                pids.add(child_pid)
                # Recursively get children of this child
                pids.update(get_pid_tree_linux(child_pid))
            except (ValueError, ProcessLookupError):
                pass
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        pass

    return pids


def get_pid_tree_psutil(pid: int) -> Set[int]:
    """Get all PIDs in process tree starting from pid (psutil implementation).

    Used on macOS and as fallback on Linux.
    """
    pids = {pid}

    try:
        import psutil
        parent = psutil.Process(pid)
        for child in parent.children(recursive=True):
            try:
                pids.add(child.pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except (ImportError, psutil.NoSuchProcess, psutil.AccessDenied):
        pass

    return pids


def get_pid_tree(pid: int, use_cache: bool = True) -> Set[int]:
    """Get all PIDs in process tree starting from pid.

    Automatically selects the appropriate implementation based on platform.
    Uses caching to improve performance.

    Args:
        pid: The root PID to start from
        use_cache: Whether to use cached results (5-second TTL)

    Returns:
        Set of all PIDs in the tree (including the root)

    """
    if use_cache:
        return _cached_get_pid_tree(pid, time.time() // 5)  # 5-second cache buckets
    return _get_pid_tree_uncached(pid)


@lru_cache(maxsize=256)
def _cached_get_pid_tree(pid: int, cache_bucket: int) -> Set[int]:
    """Cached version of get_pid_tree with 5-second TTL."""
    return _get_pid_tree_uncached(pid)


def _get_pid_tree_uncached(pid: int) -> Set[int]:
    """Uncached version of get_pid_tree."""
    if sys.platform == "linux":
        return get_pid_tree_linux(pid)
    else:
        # macOS and other platforms use psutil
        return get_pid_tree_psutil(pid)


def is_pid_alive(pid: int) -> bool:
    """Check if a process is still alive.

    Args:
        pid: Process ID to check

    Returns:
        True if process is alive, False otherwise

    """
    if pid <= 0:
        return False

    try:
        # Send signal 0 to check if process exists
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError, OSError):
        return False


def get_process_command(pid: int) -> Optional[str]:
    """Get the command name for a process.

    Args:
        pid: Process ID

    Returns:
        Command name or None if not found

    """
    try:
        if sys.platform == "linux":
            # Read from /proc/<pid>/comm
            comm_path = f"/proc/{pid}/comm"
            with open(comm_path) as f:
                return f.read().strip()
        else:
            # Use psutil on other platforms
            import psutil
            proc = psutil.Process(pid)
            return proc.name()
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return None


def get_process_start_time(pid: int) -> Optional[float]:
    """Get the start time of a process.

    Used to detect PID reuse - if a PID is reused by a new process,
    the start time will be different.

    Args:
        pid: Process ID

    Returns:
        Start time as Unix timestamp, or None if not found

    """
    try:
        if sys.platform == "linux":
            # Read from /proc/<pid>/stat (field 22 is start time in jiffies)
            stat_path = f"/proc/{pid}/stat"
            with open(stat_path) as f:
                stat = f.read().split()
            # Field 22 (0-indexed: 21) is starttime
            # Convert from jiffies to seconds (assuming 100 Hz)
            starttime_jiffies = int(stat[21])
            # Get system boot time from /proc/stat
            with open("/proc/stat") as f:
                for line in f:
                    if line.startswith("btime"):
                        boot_time = int(line.split()[1])
                        break
                else:
                    boot_time = 0
            return boot_time + (starttime_jiffies / 100.0)
        else:
            # Use psutil on other platforms
            import psutil
            proc = psutil.Process(pid)
            return proc.create_time()
    except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError, IndexError):
        return None


def is_pid_in_tree(target_pid: int, root_pid: int) -> bool:
    """Check if target_pid is in the process tree rooted at root_pid.

    Args:
        target_pid: The PID to check
        root_pid: The root of the process tree

    Returns:
        True if target_pid is in the tree, False otherwise

    """
    tree = get_pid_tree(root_pid)
    return target_pid in tree


def get_process_ancestry(pid: int) -> Set[int]:
    """Get all ancestor PIDs of a process (parent, grandparent, etc.).

    Walks up the process tree using /proc/[pid]/stat on Linux.
    Stops when reaching PID 1 (init) or when parent cannot be determined.

    Args:
        pid: The process ID to get ancestry for

    Returns:
        Set of all ancestor PIDs (does not include the input pid)

    """
    ancestors = set()
    current_pid = pid
    max_depth = 100  # Safety limit to prevent infinite loops

    for _ in range(max_depth):
        try:
            if sys.platform == "linux":
                # Read from /proc/<pid>/stat
                # Format: pid (comm) state ppid ...
                # The ppid is the 4th field (index 3)
                stat_path = f"/proc/{current_pid}/stat"
                with open(stat_path) as f:
                    stat_content = f.read()

                # Parse the stat file - handle comm with spaces by finding the last ')'
                # Format is: pid (comm) state ppid ...
                close_paren = stat_content.rfind(')')
                if close_paren == -1:
                    break

                # Get everything after the closing paren
                after_comm = stat_content[close_paren + 1:].strip()
                fields = after_comm.split()

                if len(fields) < 2:
                    break

                # ppid is the second field after the comm (state is first, ppid is second)
                ppid = int(fields[1])
            else:
                # Use psutil on other platforms
                import psutil
                proc = psutil.Process(current_pid)
                ppid = proc.ppid()

            if ppid <= 0 or ppid == current_pid:
                break

            ancestors.add(ppid)

            # Stop at init (PID 1)
            if ppid == 1:
                break

            current_pid = ppid

        except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError, IndexError):
            break

    return ancestors


def is_pid_related_to_session(client_pid: int, session_root_pid: int) -> bool:
    """Check if client_pid is related to the session (descendant or ancestor).

    This handles the case where process wrappers like 'uv run', 'npx', or 'poetry run'
    spawn processes in new process groups. In such cases, the client PID may not be
    a descendant of the session root, but the session root may be an ancestor of
    the client.

    Args:
        client_pid: The PID making the request
        session_root_pid: The root PID of the session

    Returns:
        True if client_pid is a descendant of session_root_pid,
        or if session_root_pid is in the ancestry of client_pid

    """
    # First check: is client_pid a descendant of session_root_pid?
    tree = get_pid_tree(session_root_pid)
    if client_pid in tree:
        return True

    # Second check: is session_root_pid an ancestor of client_pid?
    # This handles wrappers that spawn processes in new process groups
    ancestry = get_process_ancestry(client_pid)
    if session_root_pid in ancestry:
        return True

    return False


def clear_cache() -> None:
    """Clear the PID tree cache."""
    _cached_get_pid_tree.cache_clear()
