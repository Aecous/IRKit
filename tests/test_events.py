import copy
import json
from types import SimpleNamespace

import pytest

from irkit import board, dispatch, events, report
from irkit.cases import fresh_investigation
from irkit.verification import closure_readiness
from irkit.web import snapshot


def event():
    return dict(
        title="Service configuration changed",
        environment="lab",
        asset="host-a",
        observed="An audit record describes a service configuration change.",
        possible_causes=["An administrative operation may have changed the configuration."],
        observed_effects=[],
        potential_impacts=["The next service start may use the changed setting."],
        upstream=dict(
            question="Which identity initiated the configuration change?", priority="critical", status="open"
        ),
        downstream=dict(
            question="Did the service subsequently start?",
            priority="optional",
            status="open",
            reason="No execution claim is made in this finding; record this lead for later.",
        ),
    )


def test_event_question_requires_dispatch_and_independent_review(case, dataset):
    task = board.create_task(
        case, "ir-investigate", "Find changes", "Fixture", [dataset["id"]], event_policy_version=1
    )
    task = board.update_task(case, task["id"], task["revision"], "running")
    ref = {"dataset_id": dataset["id"], "row_id": 1}
    with pytest.raises(ValueError, match="submit_event"):
        board.submit_card(case, "Old free-text card", "observation", [ref], task_id=task["id"])
    card = events.submit_event(case, event(), [ref], "2026-01-01 UTC", task["id"])
    with pytest.raises(ValueError, match="疑似重复事件"):
        events.submit_event(case, event(), [ref], "2026-01-01 UTC", task["id"])
    board.update_task(case, task["id"], task["revision"], "completed", "Change observed", [card["id"]])
    queue = events.event_queue(case)
    assert queue["total"] == 1 and queue["questions"][0]["direction"] == "upstream"
    with pytest.raises(ValueError, match="EVENT_QUESTION_OPEN"):
        report.render_report(case, "Premature final", [], [])
    follow = board.create_task(
        case,
        "ir-investigate",
        event()["upstream"]["question"] + " Check identities in the available audit window.",
        "Fixture",
        [dataset["id"]],
        card["id"],
        "upstream",
    )
    follow = board.update_task(case, follow["id"], follow["revision"], "running")
    check = board.submit_check(
        case,
        follow["question"],
        [],
        "inconclusive",
        "Two records",
        "Identity audit unavailable; cannot infer the caller",
        task_id=follow["id"],
    )
    board.update_task(
        case, follow["id"], follow["revision"], "completed", "Bounded visibility limit", [check["id"]]
    )
    assert events.event_queue(case)["questions"][0]["state"] == "awaiting_review"
    synth = board.create_task(case, "ir-synthesize", "Review", "Fixture", [follow["id"]])
    synth = board.update_task(case, synth["id"], synth["revision"], "running")
    board.review_followup(
        case,
        follow["id"],
        synth["id"],
        "supported",
        "The limited observation and documented identity gap are supported",
    )
    assert events.event_queue(case)["total"] == 0
    assert closure_readiness(case)["ready"]
    additional = board.create_task(
        case,
        "ir-investigate",
        "Check a second possible initiating identity",
        "Fixture",
        [dataset["id"]],
        card["id"],
        "upstream",
    )
    assert events.event_queue(case)["questions"][0]["state"] == "assigned"
    additional = board.update_task(case, additional["id"], additional["revision"], "running")
    another_check = board.submit_check(
        case,
        additional["question"],
        [],
        "inconclusive",
        "Fixture",
        "Identity audit unavailable",
        task_id=additional["id"],
    )
    board.update_task(
        case,
        additional["id"],
        additional["revision"],
        "completed",
        "Documented limit",
        [another_check["id"]],
    )
    assert events.event_queue(case)["questions"][0]["state"] == "awaiting_review"
    another_synth = board.create_task(
        case, "ir-synthesize", "Review additional evidence", "Fixture", [additional["id"]]
    )
    another_synth = board.update_task(case, another_synth["id"], another_synth["revision"], "running")
    board.review_followup(
        case, additional["id"], another_synth["id"], "supported", "Documented visibility limit verified"
    )
    assert events.event_queue(case)["total"] == 0
    rendered = report.render_report(case, "Change observed; cause unknown", [], [])
    assert "Change observed; cause unknown" in case.path(rendered["path"]).read_text()
    assert "可能前因（假设）" not in case.path(rendered["path"]).read_text()
    assert (
        next(o for o in snapshot(case)["objects"] if o["id"] == card["id"])["investigation"]["upstream"][
            "state"
        ]
        == "reviewed"
    )
    updated = copy.deepcopy(event())
    updated["observed"] = "Corrected observation"
    events.revise_event(case, card["id"], card["revision"], updated, [ref], "Timestamp correction")
    assert events.event_queue(case)["total"] == 1
    assert case.get(rendered["id"])["status"] == "stale"


def test_event_boundaries_require_real_checks_and_reason(case, dataset):
    e = event()
    e["upstream"].update(status="bounded", reason="Not observable")
    with pytest.raises(ValueError, match="actual check_ids"):
        events.validate(case, e)
    e["upstream"].update(status="not_applicable", reason="")
    with pytest.raises(ValueError, match="reason"):
        events.validate(case, e)


def test_fresh_case_reuses_data_without_old_findings(case, dataset, tmp_path):
    ref = {"dataset_id": dataset["id"], "row_id": 1}
    board.submit_card(case, "Previous conclusion", "observation", [ref])
    fresh = fresh_investigation(case, "Same investigation objective", tmp_path / "web-cases")
    assert not list(fresh.all("card")) and not list(fresh.all("task"))
    assert fresh.get(dataset["id"])["row_count"] == dataset["row_count"]
    assert fresh.path(dataset["path"]).stat().st_ino == case.path(dataset["path"]).stat().st_ino
    assert json.loads((fresh.root / "case.json").read_text())["background"] == "Same investigation objective"
    case.path(dataset["path"]).unlink()
    assert fresh.path(dataset["path"]).is_file()


def test_web_fresh_execute_has_empty_analysis_board(case, dataset, tmp_path, monkeypatch):
    board.submit_card(case, "Prior finding", "observation", [{"dataset_id": dataset["id"], "row_id": 1}])
    path = case.root / "fresh-job.json"
    dispatch.save(
        path,
        dict(
            mode="fresh",
            source_case_dir=str(case.root),
            case_dir=str(case.root),
            cases_dir=str(tmp_path / "web-cases"),
            background="Investigate",
            budget=1,
            analysis_only=True,
        ),
    )
    monkeypatch.setattr(dispatch.subprocess, "run", lambda *args, **kw: SimpleNamespace(returncode=0))
    dispatch.execute(path)
    job = json.loads(path.read_text())
    assert job["case_dir"] != str(case.root)
    assert job["status"] == "incomplete"  # no mock model delivery
    from irkit.store import Store

    assert Store(job["case_dir"]).counts().get("card", 0) == 0
