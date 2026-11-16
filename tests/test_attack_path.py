"""Attack-path annotations order and group nodes without invalidating follow-ups."""

import pytest

from irkit import board, events
from irkit.integrity import fact_hash
from irkit.report_template import build_chains, attack_path_section


def event(title, stage=None):
    base = dict(
        title=title,
        environment="lab",
        asset="host-a",
        observed=f"An audit record describes: {title}.",
        possible_causes=[],
        observed_effects=[],
        potential_impacts=[],
        upstream=dict(question="prior?", priority="optional", status="open", reason="later"),
        downstream=dict(question="next?", priority="optional", status="open", reason="later"),
    )
    return base


def make_card(case, dataset, title):
    task = board.create_task(
        case, "ir-investigate", "Find", "Fixture", [dataset["id"]], event_policy_version=1
    )
    board.update_task(case, task["id"], task["revision"], "running")
    ref = {"dataset_id": dataset["id"], "row_id": 1}
    return events.submit_event(case, event(title), [ref], "2026-01-01 UTC", task["id"])


def test_annotation_does_not_change_fact_hash_or_invalidate_followups(case, dataset):
    card = make_card(case, dataset, "config write")
    before = fact_hash(case.get(card["id"], "card"))
    annotated = events.annotate_path(
        case,
        card["id"],
        card["revision"],
        stage="initial_access",
        chains=["main"],
        outcome="reached_app",
        key_time="2026-01-01T02:00:00+08:00",
    )
    assert annotated["revision"] == card["revision"] + 1
    after = fact_hash(case.get(card["id"], "card"))
    assert before == after  # annotations are not facts
    assert case.get(card["id"], "card")["event"]["stage"] == "initial_access"


def test_annotation_rejects_bad_values_and_requires_something(case, dataset):
    card = make_card(case, dataset, "x")
    with pytest.raises(ValueError, match="stage must be"):
        events.annotate_path(case, card["id"], card["revision"], stage="nonsense")
    with pytest.raises(ValueError, match="at least one"):
        events.annotate_path(case, card["id"], card["revision"])


def test_revise_event_preserves_annotations(case, dataset):
    card = make_card(case, dataset, "login")
    events.annotate_path(case, card["id"], card["revision"], stage="credential", chains=["main"])
    current = case.get(card["id"], "card")
    revised = events.revise_event(
        case, card["id"], current["revision"], event("login"), current["evidence"], "clarified"
    )
    assert revised["event"]["stage"] == "credential" and revised["event"]["chains"] == ["main"]


def test_build_chains_and_render(case, dataset):
    a = make_card(case, dataset, "enumeration")
    b = make_card(case, dataset, "admin login")
    events.annotate_path(case, a["id"], a["revision"], stage="recon", chains=["main"],
                         key_time="2026-01-01T01:00:00+08:00")
    events.annotate_path(case, b["id"], b["revision"], stage="credential", chains=["main"],
                         key_time="2026-01-01T02:00:00+08:00")
    live = [case.get(a["id"], "card"), case.get(b["id"], "card")]
    chains = build_chains(live, [])
    assert list(chains) == ["main"] and [c["id"] for c in chains["main"]] == [a["id"], b["id"]]
    lines = attack_path_section(case, live, [], lambda oid: f"[{oid}]")
    text = "\n".join(lines)
    assert "```mermaid" in text and "时间相邻" in text
    assert "没有执行/持久化" in text  # gap note: foothold without advanced stage
