"""Explicit opt-in live Claude test on bundled synthetic logs (may incur model charges)."""

import argparse
import json
import os
import signal
import subprocess
from pathlib import Path

from irkit.cli import launch_arguments
from irkit.evidence import initialize_case
from irkit.store import Store

project = Path(__file__).resolve().parents[1]
validation = project / ".validation/live-smoke"
validation.mkdir(parents=True, exist_ok=True)
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--resume-case", type=Path, help="Continue a synthetic case after a test interruption")
options = parser.parse_args()
if options.resume_case:
    case = Store(options.resume_case)
    if not case.root.is_relative_to(validation.resolve()):
        raise ValueError("Live smoke resume only accepts cases under .validation/live-smoke")
else:
    case = initialize_case(
        project / "examples/logs", validation / "cases", (project / "examples/background.txt").read_text()
    )
args, env, cwd = launch_arguments(case, print_mode=True, budget=3.0)
args[-1] += " 这是合成日志集成测试，最多各启动一个 prepare、investigate、synthesize 子 Agent，完成后停止。"
(validation / "latest_case.txt").write_text(str(case.root))
print(json.dumps({"case": str(case.root), "budget_usd": 3.0}), flush=True)
with (
    (validation / "claude-output.json").open("w") as out,
    (validation / "claude-stderr.txt").open("w") as err,
):
    process = subprocess.Popen(args, cwd=cwd, env=env, stdout=out, stderr=err, start_new_session=True)
    try:
        process.wait(timeout=900)
        print(json.dumps({"exit_code": process.returncode, "counts": case.counts()}))
    except subprocess.TimeoutExpired:
        print(json.dumps({"status": "timeout", "counts": case.counts()}))
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
