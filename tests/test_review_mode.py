"""REVIEW_MODE / IRKIT_REVIEW_MODE switches the synthesis review pass off for fast runs."""

import pytest

from irkit import board, events, report
from irkit.store import review_mode


def ev(title, observed, env="lab"):
    return dict(
        title=title,
        environment=env,
        asset="host-a",
        observed=observed,
        possible_causes=[],
        observed_effects=[],
        potential_impacts=[],
        upstream=dict(question="q", priority="optional", status="open", reason="later"),
        downstream=dict(question="q", priority="optional", status="open", reason="later"),
    )


def test_review_mode_default_full(monkeypatch):
    monkeypatch.delenv("IRKIT_REVIEW_MODE", raising=False)
    assert review_mode() == "full"
    for v in ("off", "fast", "none", "0", "false"):
        monkeypatch.setenv("IRKIT_REVIEW_MODE", v)
        assert review_mode() == "off"
    for v in ("full", "1", "true", "on"):
        monkeypatch.setenv("IRKIT_REVIEW_MODE", v)
        assert review_mode() == "full"


def _one_pending_card(case, dataset):
    """Create a card left in needs_review so the delivery gate would block in full mode."""
    t = board.create_task(case, "ir-investigate", "Find", "Fixture", [dataset["id"]], event_policy_version=1)
    t = board.update_task(case, t["id"], t["revision"], "running")
    ref = {"dataset_id": dataset["id"], "row_id": 1}
    card = events.submit_event(
        case,
        ev("Service configuration changed", "2026-01-01 00:00 +08:00 an admin write was observed on host-a"),
        [ref],
        "2026-01-01T00:00:00+08:00",
        t["id"],
    )
    board.update_task(case, t["id"], t["revision"], "completed", "Observed request", [card["id"]])
    # Revision debt after completed investigation, not an unfinished worker.
    case.update(card["id"], {"review_state": "needs_review", "review_causes": {"x": 1}})
    return card


def test_fast_mode_allows_final_report_with_pending_review(case, dataset, monkeypatch):
    _one_pending_card(case, dataset)
    monkeypatch.setenv("IRKIT_REVIEW_MODE", "full")
    with pytest.raises(ValueError):
        report.render_report(case, "Bounded", [], [], delivery="final")
    monkeypatch.setenv("IRKIT_REVIEW_MODE", "off")
    artifact = report.render_report(case, "Bounded", [], [], delivery="final")
    text = case.path(artifact["path"]).read_text()
    assert "报告未经独立综合复核" in text


def test_case_context_exposes_review_mode(case, monkeypatch):
    monkeypatch.setenv("IRKIT_REVIEW_MODE", "off")
    assert board.case_context(case)["review_mode"] == "off"


def test_review_mode_propagates_to_child_env(case, monkeypatch):
    from irkit.cli import launch_arguments

    monkeypatch.setenv("IRKIT_REVIEW_MODE", "off")
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/claude")
    args, env, _ = launch_arguments(case)
    assert env["IRKIT_REVIEW_MODE"] == "off"


def test_fast_delivery_and_completion_agree_without_synthesis(case, dataset, monkeypatch):
    from irkit import telemetry
    from irkit.completion import assess, checkpoint

    monkeypatch.setenv("IRKIT_REVIEW_MODE", "off")
    telemetry.initialize(case)
    base = checkpoint(case)
    card = _one_pending_card(case, dataset)
    artifact = report.render_report(case, "Only current evidence supports conclusions", [], [])
    telemetry.record(case, "fast", dict(type="result", is_error=False))
    # Assess in a different environment: the run's captured policy must win.
    monkeypatch.setenv("IRKIT_REVIEW_MODE", "full")
    outcome = assess(case, **base)
    assert outcome["status"] == "completed", outcome
    assert not outcome["synthesis_task_ids"]
    assert outcome["warnings"]
    assert artifact["status"] == "generated"
    assert artifact["human_review_status"] == "pending"
    assert artifact["review_mode"] == outcome["review_mode"] == "off"
    assert case.get(card["id"])["review_state"] == "needs_review"  # Never auto-approve evidence.
    text = case.path(artifact["path"]).read_text()
    assert not artifact["readiness"]["blockers"]
    assert artifact["readiness"]["review_pending"]
    assert "待复核" not in text
    assert "本报告是阶段性分析" not in text


@pytest.mark.parametrize("state", ["pending", "running", "failed"])
def test_fast_still_blocks_unfinished_investigation(case, monkeypatch, state):
    from irkit import telemetry
    from irkit.completion import assess, checkpoint

    monkeypatch.setenv("IRKIT_REVIEW_MODE", "off")
    telemetry.initialize(case)
    base = checkpoint(case)
    case.put("task", dict(role="ir-investigate", status=state))
    with pytest.raises(ValueError, match="UNFINISHED_TASK"):
        report.render_report(case, "Unfinished", [], [])
    artifact = report.render_report(case, "Unfinished", [], [], delivery="progress")
    assert artifact["status"] == "draft"
    telemetry.record(case, "fast", dict(type="result", is_error=False))
    outcome = assess(case, **base)
    assert outcome["status"] == "incomplete"
    assert "最终报告" in outcome["error"]
    assert "综合复核任务尚未交付" not in outcome["error"]


def test_fast_does_not_allow_stale_or_pending_citations(case, dataset, monkeypatch):
    monkeypatch.setenv("IRKIT_REVIEW_MODE", "off")
    card = _one_pending_card(case, dataset)
    card = case.get(card["id"])
    content = dict(
        scope_note="Fixture",
        conclusions=[
            dict(
                text="Observed",
                certainty="possible",
                evidence=[dict(object_id=card["id"], revision=card["revision"])],
            )
        ],
        impacts=[dict(text="Unknown", certainty="unknown", evidence=[])],
        recommendations=[dict(text="Obtain more logs", certainty="unknown", evidence=[])],
    )
    with pytest.raises(ValueError, match="current reviewed"):
        report.render_report(case, "Bounded", [], [], report_content=content)


@pytest.mark.parametrize("mode", ["off", "full"])
def test_recorded_evidence_limits_are_not_review_debt(case, dataset, monkeypatch, mode):
    from irkit.verification import closure_readiness

    monkeypatch.setenv("IRKIT_REVIEW_MODE", mode)
    t = board.create_task(case, "ir-investigate", "External transfer?", "Fixture", [dataset["id"]])
    t = board.update_task(case, t["id"], t["revision"], "running")
    c = board.submit_check(
        case,
        "External transfer?",
        [],
        "inconclusive",
        "Two HTTP records",
        "No packet or byte evidence supplied",
        task_id=t["id"],
        body_claim="not_required",
        body_reason="Network visibility question",
    )
    board.update_task(
        case, t["id"], t["revision"], "completed", "Cannot confirm external transfer", [c["id"]]
    )
    ready = closure_readiness(case)
    assert ready["ready"]
    assert not ready["review_pending"]
    assert ready["evidence_gaps"][0]["object_id"] == c["id"]
    case.update(c["id"], {"status": "stale"})
    ready = closure_readiness(case)
    assert not ready["evidence_gaps"]
    assert ready["review_pending"][0]["code"] == "STALE_ARTIFACT"
    assert ready["ready"] == (mode == "off")


def test_review_only_allowlist_keeps_real_work_blocking():
    from irkit.verification import classify_issues

    codes = [
        "UNFINISHED_TASK",
        "BODY_UNINSPECTED",
        "DECODING_INCOMPLETE",
        "CHECK_INCOMPLETE",
        "INPUT_COVERAGE_PENDING",
        "FOLLOWUP_NEEDS_EVIDENCE",
        "ENVIRONMENT_CONFLICT",
        "NEW_UNKNOWN_CODE",
    ]
    rows = classify_issues([dict(code=code) for code in codes], "off")
    assert all(row["blocking"] for row in rows)
    states = ["needs_review", "awaiting_review", "stale", "open", "assigned", "needs_evidence"]
    rows = classify_issues([dict(code="EVENT_QUESTION_OPEN", state=s) for s in states], "off")
    assert [r["blocking"] for r in rows] == [False, False, False, True, True, True]
    rows = classify_issues(
        [
            dict(code="STALE_ARTIFACT", kind="dataset"),
            dict(code="STALE_ARTIFACT", kind="check"),
        ],
        "off",
    )
    assert [r["blocking"] for r in rows] == [True, False]


def test_fast_blocks_open_critical_question(case, dataset, monkeypatch):
    monkeypatch.setenv("IRKIT_REVIEW_MODE", "off")
    t = board.create_task(case, "ir-investigate", "Entry", "Fixture", [dataset["id"]])
    t = board.update_task(case, t["id"], t["revision"], "running")
    event = ev("Unknown entry", "One observed request")
    event["upstream"]["priority"] = "critical"
    card = events.submit_event(
        case, event, [{"dataset_id": dataset["id"], "row_id": 1}], "2026-01-01T00:00:00Z", t["id"]
    )
    board.update_task(case, t["id"], t["revision"], "completed", "Observation only", [card["id"]])
    with pytest.raises(ValueError, match="EVENT_QUESTION_OPEN"):
        report.render_report(case, "Question still open", [], [])


def test_session_policy_is_authoritative_and_report_mismatch_blocks(case, monkeypatch):
    from irkit import telemetry
    from irkit.completion import assess, checkpoint

    monkeypatch.setenv("IRKIT_REVIEW_MODE", "off")
    telemetry.initialize(case)
    base = checkpoint(case)
    telemetry.record(case, "fast", dict(type="session_start", review_mode="off"))
    artifact = report.render_report(case, "No supported incident", [], [])
    telemetry.record(case, "fast", dict(type="result", is_error=False))
    monkeypatch.setenv("IRKIT_REVIEW_MODE", "full")
    assert assess(case, base["after_event"], base["after_change"])["status"] == "completed"
    case.update(artifact["id"], {"review_mode": "full"})
    assert "复核模式" in assess(case, **base)["error"]
