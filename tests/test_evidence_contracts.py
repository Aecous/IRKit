import base64
import gzip
import json

import duckdb
import pytest

from irkit import board, decoding, report, telemetry
from irkit.completion import assess
from irkit.evidence import initialize_case
from irkit.request_evidence import inspect_requests
from irkit.verification import closure_readiness, task_readiness


@pytest.fixture
def body_case(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    encoded = base64.b64encode(gzip.compress(b'{"action":"modify","resource":"example"}')).decode()
    rows = [
        {"request_body": encoded},
        {},
        {"request_body": "\x1f\x8bbroken"},
        {"payload": {"action": "read"}},
    ]
    (logs / "requests.jsonl").write_text("\n".join(json.dumps(row) for row in rows) + "\n")
    store = initialize_case(logs, tmp_path / "cases")
    sid = store.list("source")[0]["id"]
    con = duckdb.connect(str(store.root / "datasets/test.duckdb"))
    con.execute(
        "CREATE TABLE events(_row_id BIGINT, request_path VARCHAR, status INTEGER, "
        '_refs STRUCT(source_id VARCHAR, start BIGINT, "end" BIGINT)[])'
    )
    for n in range(1, 5):
        con.execute(
            "INSERT INTO events VALUES (?, '/operations', 200, "
            '[struct_pack(source_id := ?, start := ?, "end" := ?)])',
            [n, sid, n, n],
        )
    con.close()
    ds = store.put(
        "dataset",
        {
            "path": "datasets/test.duckdb",
            "sources": [sid],
            "status": "provisional",
            "row_count": 4,
            "quality": "synthetic",
            "schema": [{"name": "request_method", "type": "VARCHAR"}],
        },
    )
    task = board.create_task(
        store,
        "ir-investigate",
        "What operation was submitted?",
        "Four rows",
        [ds["id"]],
        requires_body_check=True,
    )
    task = board.update_task(store, task["id"], task["revision"], "running")
    return store, ds, task, sid


def test_uninspected_is_not_absent_and_failed_decode_is_not_missing(body_case):
    store, ds, task, sid = body_case
    args = (store, "Body available?", [], "inconclusive", "Exact rows", "No response body")
    with pytest.raises(ValueError, match="require inspected original rows"):
        board.submit_check(*args, task_id=task["id"], body_claim="absent")
    check = board.submit_check(*args, task_id=task["id"])
    with pytest.raises(ValueError, match="BODY_UNINSPECTED"):
        board.update_task(store, task["id"], task["revision"], "completed", "No body", [check["id"]])
    result = inspect_requests(
        store,
        [{"source_id": sid, "start": 1, "end": 1}, {"source_id": sid, "start": 3, "end": 3}],
        task["id"],
    )
    assert result["records"][0]["chain"] == ["base64", "gzip"]
    assert result["records"][1]["body_state"] == "present"
    assert result["records"][1]["decode_status"] == "failed"
    with pytest.raises(ValueError, match="contradicted"):
        board.submit_check(*args, task_id=task["id"], body_claim="absent", body_run_ids=[result["run_id"]])
    checked = board.submit_check(
        *args, task_id=task["id"], body_claim="present", body_run_ids=[result["run_id"]]
    )
    assert checked["body_evidence"][0]["selection"] == "exact_refs"
    assert checked["body_evidence"][0]["coverage"] == {"decoded": 1, "failed": 1}
    assert (
        board.update_task(
            store,
            task["id"],
            task["revision"],
            "completed",
            "One decoded body, one corrupt body; content not excluded",
            [checked["id"]],
        )["status"]
        == "completed"
    )


def test_absence_is_bounded_and_custom_body_field_supported(body_case):
    store, ds, task, sid = body_case
    missing = inspect_requests(store, [{"source_id": sid, "start": 2, "end": 2}], task["id"])
    check = board.submit_check(
        store,
        "Body absent on row 2?",
        [],
        "inconclusive",
        "Row 2 only",
        "No claim about other rows",
        task_id=task["id"],
        body_claim="absent",
        body_run_ids=[missing["run_id"]],
    )
    assert check["body_evidence"][0]["refs"] == [{"source_id": sid, "start": 2, "end": 2}]
    structured = inspect_requests(store, [{"source_id": sid, "start": 4, "end": 4}], task["id"], "payload")
    assert structured["records"][0]["decode_status"] == "decoded"
    assert structured["records"][0]["body_state"] == "present"


def test_http_metadata_does_not_automatically_require_body_inspection(body_case):
    store, ds, _, sid = body_case
    task = board.create_task(store, "ir-investigate", "Summarize response codes", "Four rows", [ds["id"]])
    assert task["requires_body_check"] is False
    task = board.update_task(store, task["id"], task["revision"], "running")
    check = board.submit_check(
        store,
        "Response codes only",
        [],
        "inconclusive",
        "Four rows",
        "No assertion about request or response content",
        task_id=task["id"],
    )
    done = board.update_task(store, task["id"], task["revision"], "completed", "Metadata only", [check["id"]])
    assert done["status"] == "completed"
    assert not list(store.all("run"))


def test_partial_decoding_and_failed_rows_cannot_prove_body_absence(body_case):
    store, ds, task, sid = body_case
    run = decoding.start_decode(store, [ds["id"]], {"request_path": "/operations"}, task_id=task["id"])
    decoding.decode_batch(store, run["id"], 1)
    args = (store, "Bodies missing?", [], "inconclusive", "Four rows", "Test scope")
    with pytest.raises(ValueError, match="requires completed"):
        board.submit_check(*args, task_id=task["id"], body_claim="absent", decode_run_ids=[run["id"]])
    done = decoding.decode_batch(store, run["id"], 10)
    assert done["coverage"] == {"absent": 2, "decoded": 1, "failed": 1}
    assert done["body_presence"]["present"] == 2
    with pytest.raises(ValueError, match="contradicted"):
        board.submit_check(*args, task_id=task["id"], body_claim="absent", decode_run_ids=[run["id"]])
    check = board.submit_check(*args, task_id=task["id"], body_claim="present", decode_run_ids=[run["id"]])
    assert check["body_evidence"][0]["candidate_count"] == 4


def test_omitting_pending_task_cannot_finalize_report(body_case):
    store, ds, task, sid = body_case
    synth = board.create_task(store, "ir-synthesize", "Review", "All evidence", [])  # omitted investigation
    synth = board.update_task(store, synth["id"], synth["revision"], "running")
    assert not closure_readiness(store)["ready"]
    with pytest.raises(ValueError, match="UNFINISHED_TASK"):
        report.render_report(store, "Investigation finished", [], [])
    progress = report.render_report(store, "Body investigation still pending", [], [], delivery="progress")
    with pytest.raises(ValueError, match="UNFINISHED_TASK"):
        board.update_task(store, synth["id"], synth["revision"], "completed", "Finished", [progress["id"]])
    board.update_task(
        store, synth["id"], synth["revision"], "partial", "Unfinished investigation", [progress["id"]]
    )
    telemetry.initialize(store)
    telemetry.record(store, "test", {"type": "result", "is_error": False})
    assert assess(store)["status"] == "incomplete"
    assert progress["delivery"] == "progress" and not progress["readiness"]["ready"]
    assert "UNFINISHED_TASK" not in store.path(progress["path"]).read_text()


def test_metadata_only_exemption_is_explicit_and_final_delivery_is_rechecked(body_case):
    store, ds, task, sid = body_case
    args = (store, "Request timing only", [], "inconclusive", "Four rows", "No payload claim")
    with pytest.raises(ValueError, match="Explain why"):
        board.submit_check(*args, task_id=task["id"], body_claim="not_required")
    check = board.submit_check(
        *args,
        task_id=task["id"],
        body_claim="not_required",
        body_reason="Only describes timestamp coverage; no claim about payload existence or semantics",
    )
    board.update_task(store, task["id"], task["revision"], "completed", "Metadata scope only", [check["id"]])
    synth = board.create_task(store, "ir-synthesize", "Review", "Metadata", [task["id"]])
    synth = board.update_task(store, synth["id"], synth["revision"], "running")
    final = report.render_report(store, "No payload conclusion", [], [])
    board.update_task(store, synth["id"], synth["revision"], "completed", "Bounded report", [final["id"]])
    telemetry.initialize(store)
    telemetry.record(store, "test", {"type": "result", "is_error": False})
    assert assess(store)["status"] == "completed"
    # Work appearing after report generation must not pass the final launcher check.
    board.create_task(store, "ir-investigate", "New evidence to verify", "Same source", [ds["id"]])
    result = assess(store)
    assert result["status"] == "incomplete"
    assert not result["closure_readiness"]["ready"]


def test_stale_card_error_names_real_artifact_and_allows_explicit_exclusion(case, dataset):
    ref = {"dataset_id": dataset["id"], "row_id": 1}
    seed = board.submit_card(case, "Read observed", "observation", [ref])
    task = board.create_task(case, "ir-investigate", "What followed?", "Fixture", [dataset["id"]], seed["id"])
    task = board.update_task(case, task["id"], task["revision"], "running")
    fact = board.submit_card(case, "Initial fact", "observation", [ref], task_id=task["id"])
    inference = board.submit_card(
        case, "Initial inference", "inference", [ref], depends_on=[fact["id"]], task_id=task["id"]
    )
    check = board.submit_check(
        case, "What followed?", [], "inconclusive", "Fixture", "No response", task_id=task["id"]
    )
    board.revise_card(case, fact["id"], fact["revision"], "Corrected fact", [ref], "Correct timing")
    artifacts = [fact["id"], inference["id"], check["id"]]
    diagnostic = task_readiness(case, task["id"], artifacts)
    assert diagnostic["issues"][0]["object_id"] == inference["id"]
    assert diagnostic["issues"][0]["stale_because"] == fact["id"]
    with pytest.raises(ValueError, match=inference["id"]):
        board.update_task(case, task["id"], task["revision"], "completed", "Corrected", artifacts)
    completed = board.update_task(
        case,
        task["id"],
        task["revision"],
        "completed",
        "Corrected; inference withdrawn",
        [fact["id"], check["id"]],
        {inference["id"]: "Incorrect ordering; not relied on"},
    )
    assert completed["excluded_artifacts"][inference["id"]]["reason"]
    assert case.get(inference["id"])["status"] == "candidate"
    assert case.get(inference["id"])["review_state"] == "needs_review"
    board.revise_card(case, seed["id"], seed["revision"], "Revised seed", [ref], "New evidence")
    rebased = board.rebase_followup(case, task["id"], completed["revision"], "Revalidate new seed")
    assert rebased["status"] == "running" and not rebased["artifact_ids"]
    assert rebased["rebase_history"][0]["previous_artifact_ids"] == [fact["id"], check["id"]]
    assert case.get(check["id"])["status"] == "stale"
    with pytest.raises(ValueError, match="STALE_ARTIFACT"):
        board.update_task(
            case, task["id"], rebased["revision"], "completed", "Old check reused", [check["id"]]
        )
