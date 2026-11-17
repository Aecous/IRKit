"""Exercise the real supervisor process without spending model budget."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from irkit import telemetry


@pytest.mark.parametrize(
    "mode,code,status",
    [
        ("complete", 0, "completed"),
        ("fast", 0, "completed"),
        ("stopped", 2, "incomplete"),
        ("timeout", 124, "interrupted"),
    ],
)
def test_launcher_lifecycle(case, tmp_path, mode, code, status):
    binary = tmp_path / "claude"
    binary.write_text(
        "#!"
        + sys.executable
        + "\n"
        + """
import json, os, time
from pathlib import Path
from irkit.store import Store
assert os.environ['CLAUDE_CODE_DISABLE_BACKGROUND_TASKS']=='1'
assert os.environ['CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS']=='0'
store=Store(Path.cwd().parent)
mode=os.environ['IRKIT_TEST_MODE']
if mode=='timeout':
    time.sleep(20)
elif mode=='fast':
    from irkit.report import render_report
    render_report(store, 'Synthetic bounded report', [], [])
elif mode=='complete':
    (store.root/'reports/test.md').write_text('Synthetic report')
    r=store.put('report',dict(path='reports/test.md',status='draft'))
    store.put('task',dict(role='ir-synthesize',status='completed',artifact_ids=[r['id']]))
else:
    store.put('task',dict(role='ir-investigate',status='running'))
    print(json.dumps(dict(type='system',subtype='task_notification',tool_use_id='child',status='stopped')),flush=True)
    print('Background tasks still running after 600s; terminating.', file=__import__('sys').stderr)
print(json.dumps(dict(type='result',is_error=False)),flush=True)
"""
    )
    binary.chmod(0o700)
    config = tmp_path / "config"
    config.mkdir()
    env = {
        **os.environ,
        "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
        "CLAUDE_CONFIG_DIR": str(config),
        "IRKIT_TEST_MODE": mode,
        "IRKIT_REVIEW_MODE": "off" if mode == "fast" else "full",
    }
    command = [
        sys.executable,
        str(Path(__file__).resolve().parents[1] / "scripts/run_case.py"),
        str(case.root),
    ]
    if mode == "timeout":
        command += ["--timeout-seconds", "1"]
    result = subprocess.run(command, env=env, timeout=15, capture_output=True, text=True)
    assert result.returncode == code, result.stderr + result.stdout
    session = telemetry.sessions(case)[0]
    assert session["ending"]["outcome"]["status"] == status
    assert (case.root / "sessions/events-1.jsonl").is_file()
    if mode == "stopped":
        assert session["ending"]["exit_code"] == 0
        assert session["ending"]["outcome"]["stopped_agent_ids"] == ["child"]
    if mode in ("complete", "fast"):
        assert json.loads((case.root / "sessions/response-1.json").read_text())["is_error"] is False
    if mode == "fast":
        assert session["ending"]["outcome"]["review_mode"] == "off"
        assert not session["ending"]["outcome"]["synthesis_task_ids"]
