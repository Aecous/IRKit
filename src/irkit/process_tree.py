"""Read POSIX process relationships for scoped cancellation."""

import os
import signal
import subprocess


def snapshot():
    result = subprocess.check_output(["ps", "-axww", "-o", "pid=,ppid=,pgid=,command="], text=True)
    processes = {}
    for line in result.splitlines():
        parts = line.split(None, 3)
        if len(parts) == 4 and all(value.isdigit() for value in parts[:3]):
            pid, parent, group = map(int, parts[:3])
            processes[pid] = (parent, group, parts[3])
    return processes


def stop_detached_descendants(root, processes):
    """Stop only process groups created by descendants of the confirmed run."""
    remaining = [root]
    groups = []
    while remaining:
        parent = remaining.pop()
        for pid, (ppid, group, _) in processes.items():
            if ppid != parent:
                continue
            remaining.append(pid)
            if pid == group and pid != os.getpgrp():
                groups.append(pid)
    for group in reversed(groups):
        try:
            os.killpg(group, signal.SIGKILL)
        except ProcessLookupError:
            pass
