import json
import os
import threading
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest

from irkit import dispatch, telemetry
from irkit.web import create_server


class HeldProcess:
    def __init__(self, args, **kwargs):
        self.args = args
        self.fd = os.dup(kwargs["pass_fds"][0])
        self.done = threading.Event()

    def wait(self):
        self.done.wait(10)
        return 0

    def finish(self):
        os.close(self.fd)
        self.done.set()


def test_dispatch_once_lock_and_restart(case, monkeypatch):
    launched = []

    def spawn(*args, **kwargs):
        p = HeldProcess(*args, **kwargs)
        launched.append(p)
        return p

    monkeypatch.setattr(dispatch.subprocess, "Popen", spawn)
    manager = dispatch.Dispatch(case.root)
    data = dict(
        request_id="test_request_001",
        mode="current",
        analysis_only=False,
        budget=10_000,
        background="Find anomalies",
    )
    job = manager.submit(data)
    try:
        assert job["budget"] == 10_000
        assert manager.submit(data)["id"] == job["id"]
        assert len(launched) == 1
        assert manager.jobs()[0]["status"] == "starting"
        restarted = dispatch.Dispatch(case.root)
        with pytest.raises(RuntimeError, match="已有任务"):
            restarted.submit({**data, "request_id": "test_request_002"})
        assert launched[0].args[1:3] == ["-m", "irkit.dispatch"]
    finally:
        launched[0].finish()
    assert manager.jobs()[0]["status"] == "interrupted"


def test_execute_prepares_new_case_and_keeps_background_as_data(case, tmp_path, monkeypatch):
    source = tmp_path / "input2"
    source.mkdir()
    (source / "access.log").write_text("example log\n")
    path = case.root / "job.json"
    job = dict(
        mode="new",
        status="starting",
        log_dir=str(source),
        cases_dir=str(tmp_path / "new-cases"),
        background="literal $(touch not-a-command)",
        budget=1,
        analysis_only=False,
    )
    dispatch.save(path, job)
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        assert kwargs == {"check": False}
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(dispatch.subprocess, "run", run)
    dispatch.execute(path)
    result = json.loads(path.read_text())
    assert result["status"] == "incomplete"
    assert "没有落盘" in result["error"]
    assert Path(result["case_dir"], "case.json").is_file()
    assert "literal $(touch not-a-command)" in path.with_suffix(".instruction.txt").read_text()
    assert "--analysis-only" not in calls[0]
    assert calls[0][3:5] == ["--budget", "1"]


def test_execute_failure_and_model_budget_error(case, monkeypatch):
    path = case.root / "job.json"
    job = dict(mode="current", case_dir=str(case.root), background="", budget=1, analysis_only=True)
    dispatch.save(path, job)

    def run(args, **kwargs):
        telemetry.record(
            case, "test_runtime", {"type": "result", "is_error": True, "subtype": "error_max_budget_usd"}
        )
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(dispatch.subprocess, "run", run)
    dispatch.execute(path)
    result = json.loads(path.read_text())
    assert result["status"] == "failed"
    assert "error_max_budget_usd" in result["error"]


def test_validation_and_case_selection(case):
    manager = dispatch.Dispatch(case.root)
    data = dict(request_id="test_request_001", mode="current", analysis_only=False)
    for budget in (0, -1, "nan", "inf"):
        with pytest.raises(ValueError):
            manager.submit({**data, "budget": budget})
    with pytest.raises(ValueError, match="尚无可用"):
        manager.submit({**data, "analysis_only": True})
    with pytest.raises(ValueError, match="Unknown case"):
        manager.case("../../etc")
    with pytest.raises(ValueError, match="绝对路径"):
        manager.submit({**data, "mode": "new", "log_dir": ""})
    with pytest.raises(ValueError, match="重叠"):
        manager.submit({**data, "mode": "new", "log_dir": str(case.root.parent)})


def test_http_post_origin_token_and_history(case, monkeypatch):
    submitted = []
    monkeypatch.setattr(
        dispatch.Dispatch,
        "submit",
        lambda self, data: submitted.append(data) or {"id": "fake", "status": "starting"},
    )
    server = create_server(case.root, 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        control = json.load(urllib.request.urlopen(base + "/api/control"))
        headers = {"Content-Type": "application/json", "Origin": base, "X-IRKit-Token": control["token"]}
        for change in ({"Origin": "https://other.example"}, {"X-IRKit-Token": "wrong"}):
            request = urllib.request.Request(base + "/api/jobs", data=b"{}", headers={**headers, **change})
            with pytest.raises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(request)
            assert error.value.code == 403
        assert not submitted
        request = urllib.request.Request(base + "/api/jobs", data=b'{"mode":"current"}', headers=headers)
        with urllib.request.urlopen(request) as response:
            assert response.status == 202
        assert submitted == [{"mode": "current"}]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_selected_fresh_investigation_pins_data_and_project(case, dataset, monkeypatch):
    launched = []

    def spawn(*args, **kwargs):
        p = HeldProcess(*args, **kwargs)
        launched.append(p)
        return p

    monkeypatch.setattr(dispatch.subprocess, "Popen", spawn)
    manager = dispatch.Dispatch(case.root)
    view = manager.projects.view(manager.jobs())
    job = manager.submit(
        dict(
            request_id="project_fresh_pinned",
            mode="fresh",
            case_id=case.root.name,
            project_id=view["project_id"],
            investigation_name="独立调查名称",
        )
    )
    try:
        assert job["dataset_ids"] == [dataset["id"]]
        assert job["source_case_dir"] == str(case.root)
        assert job["project_id"] == view["project_id"]
        assert job["investigation_name"] == "独立调查名称"
        assert job["analysis_only"] is True
    finally:
        launched[0].finish()
