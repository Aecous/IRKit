import os
import signal
import subprocess
import sys
import time

from irkit.datasets import dataset_row, publish_dataset, query_dataset, run_transform
from irkit.evidence import initialize_case, read_evidence
from irkit.execution import run_process


def test_timeout_cleans_worker_process_group(tmp_path):
    code = """
import subprocess, sys, time
from pathlib import Path
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
Path("child.pid").write_text(str(child.pid))
time.sleep(60)
"""
    result = run_process([sys.executable, "-c", code], tmp_path, timeout=1)
    assert result["status"] == "timeout"
    pid = int((tmp_path / "child.pid").read_text())
    # A terminated child can briefly remain a zombie until its new parent reaps it.
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        state = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True).stdout
        if not state.strip() or state.lstrip().startswith("Z"):
            break
        time.sleep(0.05)
    else:
        os.kill(pid, signal.SIGKILL)
        raise AssertionError("Worker descendant survived timeout")


def test_unknown_binary_custom_parser_keeps_raw_references(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "unfamiliar.dat").write_bytes(b"\x00first|7\n\x00second|11\n")
    store = initialize_case(logs, tmp_path / "cases")
    source = store.list("source")[0]
    assert source["record_kind"] == "unsupported"
    code = r"""
sid = SOURCE_IDS[0]
assert SOURCE_PATHS[sid].read_bytes().startswith(b"\x00")
for ordinal, raw in records(sid, encoding="latin-1"):
    name, value = raw.removeprefix("\x00").split("|")
    emit({"name": name, "value": int(value)}, [
        {"source_id": sid, "start": ordinal, "end": ordinal, "encoding": "latin-1"}
    ])
"""
    transformed = run_transform(store, [source["id"]], code)
    assert transformed["status"] == "succeeded", transformed
    dataset = publish_dataset(
        store, transformed["id"], "Synthetic custom binary", {"value": "integer"},
        "Two LF byte records parsed, no failures", ["SELECT * FROM {dataset_id}"],
    )
    result = query_dataset(store, [dataset["id"]], f"SELECT sum(value) AS total FROM {dataset['id']}")
    assert result["preview"] == [{"total": 18}]
    row = dataset_row(store, dataset["id"], 2)
    ref = row["_refs"][0]
    raw = read_evidence(store, ref["source_id"], ref["start"], ref["end"], ref["encoding"])
    assert raw["records"][0]["text"] == "\x00second|11"


def test_failure_keeps_diagnostic_output(tmp_path):
    result = run_process([sys.executable, "-c", "raise ValueError('synthetic failure')"], tmp_path)
    assert result["status"] == "failed"
    assert "synthetic failure" in result["stderr_tail"]
    assert (tmp_path / "stderr.txt").is_file()
