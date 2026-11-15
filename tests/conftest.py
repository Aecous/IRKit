import pytest

from irkit.datasets import publish_dataset, run_transform
from irkit.evidence import initialize_case


@pytest.fixture
def case(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "access.log").write_text(
        "2026-11-13T10:00:00Z request=r1 status=200\n2026-11-13T10:00:01Z request=r2 status=500\n"
    )
    return initialize_case(logs, tmp_path / "cases", "Synthetic test only")


@pytest.fixture
def dataset(case):
    sid = case.list("source")[0]["id"]
    run = run_transform(
        case,
        [sid],
        f"""
for n, text in records({sid!r}):
    time, req, status = text.split()
    emit({{"time": time, "request_id": req.split("=")[1], "status": int(status.split("=")[1])}},
         [{{"source_id": {sid!r}, "start": n, "end": n}}])
""",
    )
    assert run["status"] == "succeeded", run
    return publish_dataset(
        case,
        run["id"],
        "Synthetic web requests",
        {"time": "UTC", "status": "HTTP status"},
        "2/2 rows parsed; synthetic data",
        ["SELECT count(*) FROM {dataset_id}"],
    )
