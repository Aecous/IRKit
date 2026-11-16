"""REVIEW_MODE / IRKIT_REVIEW_MODE switches the synthesis review pass off for fast runs."""

import pytest

from irkit import board, events, report
from irkit.store import review_mode


def ev(title, observed, env="lab"):
    return dict(
        title=title, environment=env, asset="host-a", observed=observed,
        possible_causes=[], observed_effects=[], potential_impacts=[],
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
    board.update_task(case, t["id"], t["revision"], "running")
    ref = {"dataset_id": dataset["id"], "row_id": 1}
    card = events.submit_event(
        case,
        ev("Service configuration changed", "2026-01-01 00:00 +08:00 an admin write was observed on host-a"),
        [ref], "2026-01-01T00:00:00+08:00", t["id"],
    )
    # Force a review-pending state so closure_readiness reports a review blocker.
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
    assert "复核模式：已关闭独立综合复核" in text


def test_case_context_exposes_review_mode(case, monkeypatch):
    monkeypatch.setenv("IRKIT_REVIEW_MODE", "off")
    assert board.case_context(case)["review_mode"] == "off"


def test_review_mode_propagates_to_child_env(case, monkeypatch):
    from irkit.cli import launch_arguments

    monkeypatch.setenv("IRKIT_REVIEW_MODE", "off")
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/claude")
    args, env, _ = launch_arguments(case)
    assert env["IRKIT_REVIEW_MODE"] == "off"
