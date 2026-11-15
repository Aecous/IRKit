"""Local Python subprocess execution shared by macOS and Linux.

Workers run with the current user's OS permissions. The environment is kept
small to avoid accidentally passing model credentials to conversion code.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
from pathlib import Path


def run_process(command, run_dir, timeout=0):
    if type(timeout) is not int or timeout < 0:
        raise ValueError("Timeout must be a nonnegative integer; 0 means no deadline")
    run_dir = Path(run_dir).resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    env = {
        "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ.get("PATH", os.defpath),
        "HOME": str(run_dir),
        "TMPDIR": str(run_dir),
        "LANG": "en_US.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "OPENBLAS_NUM_THREADS": "1",
        "OMP_NUM_THREADS": "1",
    }
    out, err = run_dir / "stdout.txt", run_dir / "stderr.txt"
    with out.open("wb") as stdout, err.open("wb") as stderr:
        process = subprocess.Popen(
            list(map(str, command)),
            cwd=run_dir,
            env=env,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
        )
        timed_out = False
        try:
            process.wait(timeout=timeout or None)
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            # A worker's descendants share its process group, including shell children.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()

    def tail(path):
        if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
            return "Unsafe output file was omitted"
        with path.open("rb") as stream:
            stream.seek(max(0, path.stat().st_size - 8000))
            return stream.read().decode("utf-8", errors="replace")

    return {
        "status": "timeout" if timed_out else "succeeded" if process.returncode == 0 else "failed",
        "execution_mode": "local",
        "exit_code": process.returncode,
        "stdout_tail": tail(out),
        "stderr_tail": tail(err),
    }
