"""Observe one native Claude case session; no model-task scheduling is implemented here."""

import argparse
import fcntl
import json
import os
import signal
import subprocess
import threading
import time
from pathlib import Path

from watch_case import CaseProgress

from irkit import telemetry
from irkit.cli import launch_arguments
from irkit.completion import assess, checkpoint
from irkit.store import Store, uid

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("case_dir", type=Path)
parser.add_argument("--budget", type=float, default=8)
parser.add_argument("--instruction", default="")
parser.add_argument("--instruction-file", type=Path)
parser.add_argument("--timeout-seconds", type=int, default=0, help="会话总时限；0 表示不限时（默认）")
parser.add_argument(
    "--analysis-only", action="store_true", help="Disable data preparation and ingestion tools"
)
options = parser.parse_args()
if options.timeout_seconds < 0:
    parser.error("--timeout-seconds must be >= 0")
store = Store(options.case_dir)
session_dir = store.root / "sessions"
session_dir.mkdir(exist_ok=True)
session_lock = (session_dir / "session.lock").open("a")
try:
    fcntl.flock(session_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    raise SystemExit("该案件已有 Claude 会话运行，请等待完成后再启动") from None
args, env, cwd = launch_arguments(store, print_mode=True, budget=options.budget)
instruction = (
    options.instruction_file.read_text(encoding="utf-8") if options.instruction_file else options.instruction
)
args[-1] += "\n" + instruction
args[args.index("--output-format") + 1] = "stream-json"
args.insert(1, "--verbose")
telemetry.initialize(store)
baseline = checkpoint(store)
runtime_id = uid("session")
telemetry.record(store, runtime_id, {"type": "session_start", "instruction": args[-1]})
if options.analysis_only:
    args[-1:-1] = [
        "--disallowedTools",
        ",".join(
            [
                "Agent(ir-prepare)",
                "mcp__ir__start_jsonl_ingest",
                "mcp__ir__resume_jsonl_ingest",
                "mcp__ir__run_transform",
                "mcp__ir__publish_dataset",
                "mcp__ir__supersede_dataset",
            ]
        ),
        "--",
    ]
output_dir = store.root / "sessions"
output_dir.mkdir(exist_ok=True)
sequence = (
    max(
        (
            int(path.stem.rsplit("-", 1)[-1])
            for path in output_dir.iterdir()
            if path.stem.startswith(("response-", "stderr-", "events-"))
            and path.stem.rsplit("-", 1)[-1].isdigit()
        ),
        default=0,
    )
    + 1
)
response_path = output_dir / f"response-{sequence}.json"
stderr_path = output_dir / f"stderr-{sequence}.txt"
print(
    json.dumps(
        {
            "case": str(store.root),
            "session_number": sequence,
            "response": str(response_path),
            "stderr": str(stderr_path),
        },
        ensure_ascii=False,
    ),
    flush=True,
)
progress = CaseProgress(store.root)
with stderr_path.open("w") as err:
    try:
        proc = subprocess.Popen(
            args, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=err, text=True, start_new_session=True
        )
    except OSError as exc:
        telemetry.record(store, runtime_id, {"type": "session_end", "exit_code": 127, "reason": str(exc)})
        raise
    stream_path = output_dir / f"events-{sequence}.jsonl"
    stream_errors = []

    def capture():
        try:
            with stream_path.open("w") as stream:
                for line in proc.stdout:
                    stream.write(line)
                    stream.flush()
                    try:
                        event = json.loads(line)
                    except ValueError:
                        continue
                    try:
                        telemetry.record(store, runtime_id, event)
                    except Exception as exc:
                        # Keep draining and retaining the original transcript even if its DB projection fails.
                        if len(stream_errors) < 10:
                            stream_errors.append(str(exc))
                    if event.get("type") == "result":
                        response_path.write_text(json.dumps(event, ensure_ascii=False))
        except Exception as exc:
            stream_errors.append(str(exc))

    reader = threading.Thread(target=capture, daemon=True)
    reader.start()
    deadline = time.monotonic() + options.timeout_seconds if options.timeout_seconds else None
    end_reason = "finished"
    try:
        while True:
            progress.show()
            remaining = deadline - time.monotonic() if deadline else 5
            if remaining <= 0:
                raise subprocess.TimeoutExpired(args[0], options.timeout_seconds)
            try:
                proc.wait(timeout=min(5, remaining))
            except subprocess.TimeoutExpired:
                continue
            break
        reader.join(timeout=10)
        progress.show()
        print(json.dumps({"exit_code": proc.returncode, "counts": store.counts()}), flush=True)
        outcome = assess(store, **baseline, exit_code=proc.returncode)
        if stream_errors or reader.is_alive():
            outcome.update(status="incomplete", error="会话记录不完整，无法确认交付")
        print(json.dumps({"outcome": outcome}, ensure_ascii=False), flush=True)
        raise SystemExit(
            (0 if outcome["status"] == "completed" else 2)
            if proc.returncode == 0
            else proc.returncode
            if proc.returncode >= 0
            else 128 - proc.returncode
        )
    except subprocess.TimeoutExpired:
        end_reason = "timeout"
        print(json.dumps({"status": "session_timeout", "counts": store.counts()}), flush=True)
        raise SystemExit(124)
    except KeyboardInterrupt:
        end_reason = "interrupted"
        raise
    finally:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
        reader.join(timeout=10)
        telemetry.record(
            store,
            runtime_id,
            {
                "type": "session_end",
                "exit_code": proc.returncode,
                "reason": end_reason,
                "capture_errors": stream_errors,
                "capture_incomplete": reader.is_alive(),
                "outcome": locals().get("outcome", {"status": "interrupted", "error": end_reason}),
            },
        )
