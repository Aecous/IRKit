import json
import threading
import urllib.error
import urllib.request

import pytest

from irkit import telemetry
from irkit.cases import fresh_investigation
from irkit.dispatch import Dispatch, save
from irkit.web import create_server


def registered(case, dataset):
    child = fresh_investigation(case, "Independent")
    manager = Dispatch(case.root)
    job = dict(
        id="job_project_test",
        mode="fresh",
        status="completed",
        created="2026-01-01",
        updated="2027-01-01",
        case_dir=str(child.root),
        source_case_dir=str(case.root),
    )
    save(manager.directory / (job["id"] + ".json"), job)
    return manager, child, job


def test_migration_lineage_and_reversible_deletion(case, dataset):
    manager, child, job = registered(case, dataset)
    index = manager.projects
    view = index.view(manager.jobs())
    pid = view["project_id"]
    assert len(view["projects"]) == 1
    assert {c["id"] for c in view["investigations"]} == {case.root.name, child.root.name}
    assert index.view(manager.jobs())["project_id"] == pid
    before = child.db.read_bytes()
    index.change("trash", "run", job["id"], jobs=manager.jobs())
    assert not index.view(manager.jobs())["jobs"][0]["visible"]
    assert child.db.read_bytes() == before
    index.change("restore", "run", job["id"], jobs=manager.jobs())
    index.change("trash", "investigation", child.root.name, jobs=manager.jobs())
    with pytest.raises(ValueError, match="Unknown case"):
        manager.case(child.root.name, pid)
    assert child.db.read_bytes() == before
    index.change("restore", "investigation", child.root.name, jobs=manager.jobs())
    assert manager.case(child.root.name, pid).root == child.root
    index.change("trash", "project", pid, jobs=manager.jobs())
    assert index.view(manager.jobs())["project_id"] is None
    index.change("restore", "project", pid, jobs=manager.jobs())
    assert index.view(manager.jobs())["jobs"][0]["visible"]


def test_empty_project_and_cross_project_selection(case, dataset):
    manager, child, job = registered(case, dataset)
    other = manager.projects.change("create", name="隔离项目", jobs=manager.jobs())
    view = manager.projects.view(manager.jobs(), other["id"])
    assert view["case_id"] is None
    with pytest.raises(ValueError, match="不属于"):
        manager.case(child.root.name, other["id"])
    with pytest.raises(ValueError, match="不属于"):
        manager.submit(
            dict(
                request_id="wrong_project_001", mode="fresh", project_id=other["id"], case_id=child.root.name
            )
        )
    with pytest.raises(ValueError, match="snapshot"):
        fresh_investigation(child, "", dataset_ids=["ds_missing"])


def test_delete_rechecks_new_active_job_under_lock(case, dataset):
    manager, child, job = registered(case, dataset)
    stale_jobs = manager.jobs()
    pid = manager.projects.view(stale_jobs)["project_id"]
    # Simulate submission racing a deletion whose initial jobs snapshot is stale.
    active = {**job, "id": "job_new_running", "project_id": pid, "status": "running"}
    save(manager.directory / (active["id"] + ".json"), active)
    for kind, oid in [
        ("project", pid),
        ("investigation", child.root.name),
        ("investigation", case.root.name),
    ]:
        with pytest.raises(RuntimeError, match="运行"):
            manager.projects.change("trash", kind, oid, jobs=stale_jobs)


def test_http_scope_and_hidden_session(case, dataset):
    manager, child, job = registered(case, dataset)
    telemetry.initialize(child)
    telemetry.record(child, "session_project_test", {"type": "session_start", "instruction": "Synthetic"})
    other = manager.projects.change("create", name="Other", jobs=manager.jobs())
    view = manager.projects.view(manager.jobs())
    server = create_server(case.root, 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"

    def get(path):
        with urllib.request.urlopen(base + path) as r:
            return json.load(r)

    try:
        scoped = f"?project={view['project_id']}&case={child.root.name}"
        assert get("/api/sessions" + scoped)
        for endpoint in ("snapshot", "sessions", "raw"):
            with pytest.raises(urllib.error.HTTPError) as exc:
                get(f"/api/{endpoint}?project={other['id']}&case={child.root.name}")
            assert exc.value.code == 400
        manager.projects.change("trash", "run", job["id"], jobs=manager.jobs())
        assert get("/api/sessions" + scoped) == []
        with pytest.raises(urllib.error.HTTPError):
            get("/api/session-context" + scoped + "&run=session_project_test")
        assert get("/api/workspace?project=" + other["id"])["case_id"] is None
        token = get("/api/control")["token"]
        req = urllib.request.Request(
            base + "/api/workspace",
            data=json.dumps(dict(action="create", name="HTTP project")).encode(),
            headers={"Content-Type": "application/json", "Origin": base, "X-IRKit-Token": token},
        )
        with urllib.request.urlopen(req) as r:
            assert json.load(r)["name"] == "HTTP project"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
