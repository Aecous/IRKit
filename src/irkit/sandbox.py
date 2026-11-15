"""macOS execution boundary; never falls back to unsandboxed execution."""

from __future__ import annotations

import json
import os
import platform
import signal
import subprocess
import sys
from pathlib import Path


def run_isolated(command, run_dir, readable=(), timeout=90, file_limit_mb=256):
    if platform.system() != "Darwin" or not Path("/usr/bin/sandbox-exec").exists():
        raise RuntimeError("This version requires macOS sandbox-exec; execution refused")
    if not 1 <= timeout <= 1800 or not 1 <= file_limit_mb <= 16384:
        raise ValueError("Execution limit out of range")
    run_dir = Path(run_dir).resolve()
    runtime = {Path(sys.prefix).resolve(), Path(sys.base_prefix).resolve(), Path(__file__).parent.resolve()}
    allowed = runtime | {Path(p).resolve() for p in readable} | {run_dir}
    rules = [
        "(version 1)",
        "(deny default)",
        "(allow process-exec process-fork)",
        "(allow signal (target self))",
        "(allow sysctl-read)",
        "(allow file-read-metadata)",
        '(allow file-read* (subpath "/System/Library") (subpath "/usr/lib") '
        '(subpath "/usr/share/locale") (literal "/dev/urandom") (literal "/dev/random") '
        '(literal "/dev/null") (literal "/dev/dtracehelper"))',
        '(allow file-write* (literal "/dev/null"))',
    ]
    for path in sorted(allowed):
        clause = "subpath" if path.is_dir() else "literal"
        rules.append(f"(allow file-read* ({clause} {json.dumps(str(path), ensure_ascii=False)}))")
    for ancestor in sorted({p for path in allowed for p in path.parents}):
        rules.append(f"(allow file-read* (literal {json.dumps(str(ancestor), ensure_ascii=False)}))")
    rules.append(f"(allow file-write* (subpath {json.dumps(str(run_dir), ensure_ascii=False)}))")
    profile = run_dir / "sandbox.sb"
    profile.write_text("\n".join(rules))
    env = {
        "PATH": f"{Path(sys.executable).parent}:/usr/bin:/bin",
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
            [
                "/usr/bin/sandbox-exec",
                "-f",
                str(profile),
                sys.executable,
                "-I",
                str(Path(__file__).with_name("limitexec.py")),
                str(timeout),
                str(file_limit_mb),
                *map(str, command),
            ],
            cwd=run_dir,
            env=env,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
        )
        timed_out = False
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            # Also remove descendants left running after their parent exits.
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
        "exit_code": process.returncode,
        "stdout_tail": tail(out),
        "stderr_tail": tail(err),
    }
