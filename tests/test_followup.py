import pytest

from irkit import board, report
from irkit.datasets import query_dataset


def test_followup_requires_linked_artifacts_and_synthesis_review(case, dataset):
    did = dataset["id"]
    ref = {"dataset_id": did, "row_id": 1}
    parent = board.submit_card(case, "A management endpoint was read.", "observation", [ref])
    task = board.create_task(
        case,
        "ir-investigate",
        "Was a write observed before the read?",
        "First synthetic dataset only",
        [did],
        parent["id"],
    )
    tid = task["id"]
    assert parent["id"] in task["input_ids"]
    task = board.update_task(case, tid, task["revision"], "running")
    run = query_dataset(case, [did], f"SELECT _row_id FROM {did} WHERE status=500")
    check = board.submit_check(
        case,
        task["question"],
        [run["id"]],
        "hits",
        "Two synthetic rows",
        "Backend audit missing",
        task_id=tid,
    )
    with pytest.raises(ValueError, match="requires a new evidence card"):
        board.update_task(case, tid, task["revision"], "completed", "Request observed", [check["id"]])
    card = board.submit_card(
        case, "One 500 response was observed.", "observation", [{"dataset_id": did, "row_id": 2}], task_id=tid
    )
    assert card["depends_on"] == [parent["id"]]
    task = board.update_task(
        case, tid, task["revision"], "completed", "Request observed", [card["id"], check["id"]]
    )

    synthesis = board.create_task(case, "ir-synthesize", "Review", "Synthetic case", [tid])
    synthesis = board.update_task(case, synthesis["id"], synthesis["revision"], "running")
    sid = synthesis["id"]
    with pytest.raises(ValueError, match="FOLLOWUP_UNREVIEWED"):
        board.update_task(case, sid, synthesis["revision"], "completed", "Review", [check["id"]])
    with pytest.raises(ValueError, match="FOLLOWUP_UNREVIEWED"):
        report.render_report(case, "Premature report", [], [])
    board.review_followup(
        case, tid, sid, "needs_more_evidence", "HTTP status does not establish application state"
    )
    with pytest.raises(ValueError, match="FOLLOWUP_NEEDS_EVIDENCE"):
        report.render_report(case, "Premature final", [], [])
    artifact = report.render_report(case, "Request observed", [], [], delivery="progress")
    content = case.path(artifact["path"]).read_text()
    for value in (
        parent["id"],
        tid,
        "Two synthetic rows",
        "Backend audit missing",
        run["id"],
        "仍需补证",
        sid,
    ):
        assert value in content
    board.review_followup(
        case, tid, sid, "supported", "Bounded HTTP observation supported; no claim of application success"
    )
    artifact = report.render_report(case, "Bounded request observation", [], [])
    board.update_task(case, sid, synthesis["revision"], "completed", "Review recorded", [artifact["id"]])
    assert case.get(card["id"])["status"] == "candidate"
    board.revise_card(
        case, card["id"], card["revision"], "Corrected", [{"dataset_id": did, "row_id": 2}], "clarify"
    )
    with pytest.raises(ValueError, match="FOLLOWUP_UNREVIEWED"):
        report.render_report(case, "Request observed", [], [])
    board.revise_card(case, parent["id"], parent["revision"], "Updated starting point", [ref], "New context")
    historical = report.render_report(
        case, "Historical task needs fresh investigation", [], [], delivery="progress"
    )
    assert "起点卡片已变更，需重新补证" in case.path(historical["path"]).read_text()


def test_followup_negative_check_and_wrong_task_rejected(case, dataset):
    did = dataset["id"]
    parent = board.submit_card(case, "Seed", "observation", [{"dataset_id": did, "row_id": 1}])
    task = board.create_task(
        case, "ir-investigate", "Were there other records?", "Fixture", [did], parent["id"]
    )
    task = board.update_task(case, task["id"], task["revision"], "running")
    other = board.submit_check(case, "Unrelated", [], "inconclusive", "Outside scope", "No data")
    with pytest.raises(ValueError, match="linked to this task"):
        board.update_task(case, task["id"], task["revision"], "completed", "Unknown", [other["id"]])
    run = query_dataset(case, [did], f"SELECT _row_id FROM {did} WHERE status=999")
    check = board.submit_check(
        case,
        task["question"],
        [run["id"]],
        "zero_hits",
        "Status 999",
        "Only this fixture",
        task_id=task["id"],
    )
    completed = board.update_task(
        case, task["id"], task["revision"], "completed", "No matching rows", [check["id"]]
    )
    assert completed["status"] == "completed"
