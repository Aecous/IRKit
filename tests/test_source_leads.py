import copy
import json

import pytest

from irkit import board, events, integrity, report, telemetry
from irkit import source_leads as sl
from irkit.completion import assess
from irkit.datasets import publish_dataset, query_dataset, run_transform
from irkit.evidence import initialize_case
from irkit.verification import closure_readiness
from irkit.web import snapshot


@pytest.fixture
def lab(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    rows = [
        dict(
            event_time=f"2026-01-01T00:00:0{i}Z",
            environment="lab",
            asset="node-a",
            client=ip,
            action=action,
            status=status,
            forwarded=ip + ", 10.0.0.1",
        )
        for i, (ip, action, status) in enumerate(
            [
                ("192.0.2.1", "authenticate", "denied"),
                ("192.0.2.10", "inspect", "accepted"),
                ("192.0.2.1", "change_setting", "accepted"),
                ("192.0.2.1", "export", "accepted"),
            ]
        )
    ]
    (logs / "audit.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    store = initialize_case(logs, tmp_path / "cases", "Synthetic source behavior audit")
    sid = store.list("source")[0]["id"]
    run = run_transform(
        store,
        [sid],
        f'import json\nfor n,line in records({sid!r}):\n emit(json.loads(line), [{{"source_id":{sid!r},"start":n,"end":n}}])',
    )
    ds = publish_dataset(
        store, run["id"], "audit", {"event_time": "UTC"}, "4/4 records", ["SELECT * FROM {dataset_id}"]
    )
    return store, ds, rows


def event_for(ds, row, title="Observed action", level="application", lead_ids=None):
    q = dict(
        question="",
        priority="optional",
        status="not_applicable",
        reason="Synthetic bounded test",
        check_ids=[],
    )
    ref = {"dataset_id": ds["id"], "row_id": row}
    e = dict(
        title=title,
        environment="lab",
        asset="node-a",
        observed=title,
        possible_causes=[],
        observed_effects=[],
        potential_impacts=[],
        upstream=q,
        downstream=q,
        claims=[
            dict(
                key="observed",
                statement=title,
                level=level,
                evidence=[ref],
                scope=dict(environment="lab", dimensions={"asset": ["node-a"]}),
            )
        ],
    )
    if lead_ids is not None:
        e["source_lead_ids"] = lead_ids
    return e, ref


def card_for(store, ds, row=1, title="Observed action", lead_ids=None, task=None):
    own = task is None
    task = task or board.create_task(store, "ir-investigate", "Initial investigation", "lab", [ds["id"]])
    if task["status"] == "pending":
        task = board.update_task(store, task["id"], task["revision"], "running")
    e, ref = event_for(ds, row, title, lead_ids=lead_ids)
    card = events.submit_event(store, e, [ref], f"2026-01-01T00:00:0{row - 1}Z", task["id"])
    if own:
        board.update_task(
            store, task["id"], task["revision"], "completed", "Observed bounded action", [card["id"]]
        )
    return card


def synth(store):
    t = board.create_task(store, "ir-synthesize", "Independent review", "All current evidence", [])
    return board.update_task(store, t["id"], t["revision"], "running")


def test_review_plan_orders_parents_and_keeps_revision_guard(lab):
    store, ds, _ = lab
    a = card_for(store, ds)
    b = board.submit_card(store, "Dependent observation", "inference", a["evidence"], depends_on=[a["id"]])
    store.update(a["id"], {"review_state": "needs_review"}, invalidate=True)
    plan = integrity.review_plan(store)
    assert a["id"] in [x["id"] for x in plan["ready"]]
    assert b["id"] in [x["id"] for x in plan["blocked"]]
    t = synth(store)
    with pytest.raises(ValueError, match="Revision conflict"):
        integrity.resolve_review(store, a["id"], a["revision"], "retain", "Check current version", t["id"])
    current = store.get(a["id"])
    integrity.resolve_review(
        store, a["id"], current["revision"], "retain", "Reviewed unchanged observed fact", t["id"]
    )
    assert b["id"] in [x["id"] for x in integrity.review_plan(store)["ready"]]


def test_explicit_environment_alias_preserves_cards_and_conflicts(lab):
    store, ds, _ = lab
    a = card_for(store, ds)
    b = card_for(store, ds, 3, title="Another action")
    e = copy.deepcopy(b["event"])
    e["environment"] = "Laboratory"
    e["claims"][0]["scope"]["environment"] = "Laboratory"
    b = events.revise_event(store, b["id"], b["revision"], e, [], "Explicit environment spelling")
    before = {x["id"]: x["revision"] for x in (a, b)}
    t = synth(store)
    alias = integrity.register_environment_alias(
        store,
        "lab",
        ["lab", "Laboratory"],
        [a["id"], b["id"]],
        "Inventory confirms these two labels denote the same lab",
        t["id"],
    )
    assert integrity.environment_names(store)["Laboratory"] == "lab"
    assert all(store.get(cid)["revision"] == rev for cid, rev in before.items())
    assert alias["id"] in integrity.delivery_snapshot(store)
    with pytest.raises(ValueError, match="Each alias"):
        integrity.register_environment_alias(
            store, "lab", ["lab", "production"], [a["id"]], "Not present in the evidence", t["id"]
        )


def test_resume_lifecycle_context_and_filtered_history(lab):
    store, _, _ = lab
    telemetry.initialize(store)
    for event in [
        {
            "type": "assistant",
            "message": {
                "content": [
                    {
                        "type": "tool_use",
                        "id": "original",
                        "name": "Agent",
                        "input": {"subagent_type": "ir-synthesize", "prompt": "task_1234567890abcdef"},
                    }
                ]
            },
        },
        {
            "type": "system",
            "subtype": "task_started",
            "task_id": "native",
            "tool_use_id": "original",
            "subagent_type": "ir-synthesize",
        },
        {
            "type": "user",
            "message": {"content": [{"type": "tool_result", "tool_use_id": "original", "content": "done"}]},
        },
        {
            "type": "system",
            "subtype": "task_started",
            "task_id": "native",
            "tool_use_id": "resumed",
            "subagent_type": "ir-synthesize",
        },
        {
            "type": "assistant",
            "parent_tool_use_id": "original",
            "message": {"content": [{"type": "text", "text": "Inspecting current evidence"}]},
        },
        {"type": "tool_progress", "parent_tool_use_id": "resumed", "heartbeat": True},
        {
            "type": "system",
            "subtype": "task_notification",
            "task_id": "native",
            "tool_use_id": "resumed",
            "status": "completed",
        },
    ]:
        telemetry.record(store, "test", event)
    nav = telemetry.context(store, "test")
    assert telemetry.agent_aliases(nav)["resumed"] == "original"
    rows = telemetry.history(store, "test", agent_id="original")
    assert {r["agent_id"] for r in rows} == {"original", "resumed"}
    assert telemetry.history(store, "another", agent_id="original") == []
    assert any(e["payload"].get("subtype") == "task_notification" for e in nav)


def content(card, certainty="possible"):
    ref = dict(object_id=card["id"], revision=card["revision"], claim_key="observed")
    return dict(
        scope_note="All synthetic lab audit records; UTC timestamps",
        conclusions=[dict(text="Recorded operation observed", certainty="confirmed", evidence=[ref])],
        impacts=[
            dict(
                text="Application effect remains bounded to this audit result",
                certainty=certainty,
                evidence=[ref],
            )
        ],
        recommendations=[dict(text="Verify permission baseline", certainty="unknown", evidence=[])],
    )


def test_confirmed_impact_rejects_http_only_evidence(lab):
    from irkit.report_template import validate

    store, ds, _ = lab
    card = card_for(store, ds)
    e = copy.deepcopy(card["event"])
    e["claims"][0]["level"] = "response"
    card = events.revise_event(store, card["id"], card["revision"], e, [], "HTTP response only")
    with pytest.raises(ValueError, match="application-level"):
        validate(store, content(card, "confirmed"))
    assert validate(store, content(card, "possible"))


def test_report_timeline_sorts_known_offsets_and_keeps_unknown_last(lab):
    from irkit.report_template import event_order

    rows = [
        dict(id="a", time_range="2026-01-01T09:00:00+08:00"),
        dict(id="b", time_range="2026-01-01T00:30:00Z"),
        dict(id="c", time_range="unknown"),
    ]
    assert [r["id"] for r in sorted(rows, key=event_order)] == ["b", "a", "c"]


def source(check_ids=None, **values):
    return dict(
        address="192.0.2.1",
        field="client",
        match_mode="exact",
        attribution="direct_peer",
        check_ids=check_ids or [],
        **values,
    )


def attach(store, card, sources):
    e = copy.deepcopy(card["event"])
    e["sources"] = sources
    return events.revise_event(store, card["id"], card["revision"], e, [], "Source behavior evidence")


def test_projection_is_readonly_and_separates_source_trust(lab):
    store, ds, _ = lab
    card = attach(store, card_for(store, ds), [source()])
    other = source()
    other.update(field="forwarded", match_mode="forwarded_first", attribution="unverified")
    attach(store, card_for(store, ds, 2, "Other event"), [other])
    before = store.counts()
    a = sl.source_overview(store, limit=1)
    b = sl.source_overview(store, limit=1, offset=a["next_offset"])
    assert a["total"] == 2 and b["next_offset"] is None
    assert a["sources"][0]["id"] != b["sources"][0]["id"]
    assert a["sources"][0]["gaps"]
    assert store.counts() == before and not list(store.all("source_lead"))
    assert len([o for o in snapshot(store)["objects"] if o["kind"] == "source_view"]) == 2
    # Target/asset IPs are never inferred to be attackers.
    store.update(card["id"], {"entities": ["192.0.2.99"]})
    assert {x["address"] for x in sl.aggregate(store)} == {"192.0.2.1"}


def test_check_attachment_keeps_evidence_and_followup_current(lab):
    store, ds, _ = lab
    card = attach(store, card_for(store, ds), [source()])
    follow = board.create_task(
        store, "ir-investigate", "Find other source operations", "Lab day", [ds["id"]], card["id"]
    )
    follow = board.update_task(store, follow["id"], follow["revision"], "running")
    run = query_dataset(store, [ds["id"]], f"SELECT * FROM {ds['id']} WHERE client='192.0.2.1'")
    check = board.submit_check(
        store,
        "Find other source operations",
        [run["id"]],
        "hits",
        "lab / node-a / 2026-01-01 UTC / client=192.0.2.1; all 3 returned rows",
        "No permission baseline",
        task_id=follow["id"],
        conclusion="Authentication denied, then setting change and export",
    )
    fact = integrity.fact_hash(card)
    card = attach(store, card, [source([check["id"]])])
    assert integrity.fact_hash(card) == fact
    assert store.get(check["id"])["status"] == "candidate"
    assert not integrity.parent_changed(store.get(follow["id"]), card)
    row = sl.aggregate(store)[0]
    assert row["checks"][0]["current"] and row["checks"][0]["query_ids"] == [run["id"]]
    assert row["checks"][0]["conclusion"].startswith("Authentication denied")
    report_obj = report.render_report(store, "Progress", [], [], delivery="progress")
    text = store.path(report_obj["path"]).read_text()
    assert "Authentication denied" in text and "No permission baseline" in text
    assert check["id"] in text and card["id"] in text
    store.update(check["id"], {"status": "stale"})
    row = sl.aggregate(store)[0]
    assert not row["checks"][0]["current"] and row["gaps"]
    # A changed source identity is a changed fact; merely attaching a check wasn't.
    changed = source()
    changed["address"] = "192.0.2.2"
    updated = attach(store, card, [changed])
    assert integrity.fact_hash(updated) != fact


def test_card_revisions_preserve_or_explicitly_withdraw_source_associations(lab):
    store, ds, _ = lab
    card = attach(store, card_for(store, ds), [source()])
    e = copy.deepcopy(card["event"])
    del e["sources"]
    card = events.revise_event(store, card["id"], card["revision"], e, [], "Wording only")
    assert card["event"]["sources"]
    attach(store, card, [])
    assert sl.aggregate(store) == []
    with store.transaction() as con:
        history = con.execute("SELECT detail FROM changes WHERE object_id=?", (card["id"],)).fetchall()
    assert any("192.0.2.1" in h[0] for h in history)


def test_legacy_source_records_are_readable_without_blocking_event_work(lab):
    store, ds, _ = lab
    card = card_for(store, ds)
    lead = store.put(
        "source_lead",
        dict(
            address="192.0.2.1",
            field="client",
            match_mode="exact",
            attribution="unverified",
            status="candidate",
        ),
    )
    e = copy.deepcopy(card["event"])
    e["source_lead_ids"] = [lead["id"]]
    card = events.revise_event(store, card["id"], card["revision"], e, [], "Legacy fixture")
    task = board.create_task(store, "ir-investigate", "Legacy source pass", "Lab", [ds["id"]])
    task = store.update(task["id"], {"source_lead_id": lead["id"]})
    before = store.get(lead["id"])
    assert closure_readiness(store)["ready"]
    telemetry.initialize(store)
    assert task["id"] not in assess(store)["unfinished_task_ids"]
    row = sl.aggregate(store)[0]
    assert row["legacy_task_ids"] == [task["id"]] and row["gaps"]
    assert store.get(lead["id"]) == before
    # Genuine event follow-up still blocks even if a legacy source marker is present.
    follow = board.create_task(
        store, "ir-investigate", "Missing result evidence", "Lab", [ds["id"]], card["id"]
    )
    store.update(follow["id"], {"source_lead_id": lead["id"]})
    assert any(
        i["code"] == "UNFINISHED_TASK" and i["object_id"] == follow["id"]
        for i in closure_readiness(store)["issues"]
    )
    attach(store, card, [])
    assert sl.aggregate(store) == []


def test_validation_rejects_foreign_checks_and_bad_sources(lab):
    store, ds, _ = lab
    e, _ = event_for(ds, 1)
    for invalid in [
        source(["check_foreign"]),
        {**source(), "address": "not-ip"},
        {**source(), "match_mode": "anything"},
    ]:
        with pytest.raises(ValueError):
            events.validate(store, {**e, "sources": [invalid]})
    with pytest.raises(ValueError, match="Duplicate"):
        events.validate(store, {**e, "sources": [source(), source()]})


def test_tools_expose_event_sources_without_second_workflow(lab):
    import asyncio

    from irkit.mcpserver import build_server
    from irkit.templates import MAIN, ROLE_TOOLS, ROLES

    store, _, _ = lab
    schema = {t.name: t.inputSchema for t in asyncio.run(build_server(store.root).list_tools())}
    removed = {
        "register_source_lead",
        "source_queue",
        "plan_source_review",
        "complete_source_review",
        "review_source_task",
        "source_behavior_overview",
    }
    assert not removed & schema.keys()
    assert "source_overview" in schema and "conclusion" in schema["submit_check"]["properties"]
    assert "EventSource" in schema["submit_event"]["$defs"]
    for role, names in ROLE_TOOLS.items():
        assert set(names) <= schema.keys()
        assert not removed & set(names)
        assert "event.sources" in ROLES[role]
    assert "不为每个 IP 固定派任务" in MAIN


def test_five_chapter_final_and_current_citations_remain_required(lab):
    store, ds, _ = lab
    card = attach(store, card_for(store, ds), [source()])
    reviewer = synth(store)
    integrity.review_delivery(
        store, reviewer["id"], {card["id"]: "Observed audit and limits checked"}, "Scope checked"
    )
    result = report.render_report(
        store, "Bounded result", ["Permission baseline missing"], [], report_content=content(card)
    )
    text = store.path(result["path"]).read_text()
    headings = [line for line in text.splitlines() if line.startswith("## ")][:5]
    assert [x[3] for x in headings] == list("12345")
    assert "192.0.2.1" in text and "尚无当前有效的来源行为检查" in text
    wrong = content(card)
    wrong["conclusions"][0]["evidence"][0]["revision"] = 0
    with pytest.raises(ValueError, match="current"):
        report.render_report(store, "Wrong reference", [], [], report_content=wrong)


def test_legacy_check_scope_is_not_assigned_to_later_cards(lab):
    store, ds, _ = lab
    lead = store.put(
        "source_lead",
        dict(
            address="192.0.2.1",
            field="client",
            match_mode="exact",
            attribution="unverified",
            status="candidate",
        ),
    )
    before = card_for(store, ds, lead_ids=[lead["id"]])
    task = board.create_task(store, "ir-investigate", "Old source inspection", "First event only", [ds["id"]])
    task = board.update_task(store, task["id"], task["revision"], "running")
    check = board.submit_check(
        store,
        "Old behavior question",
        [],
        "inconclusive",
        "First event only",
        "No application audit",
        task_id=task["id"],
    )
    store.update(
        task["id"],
        dict(
            source_lead_id=lead["id"],
            source_snapshot={"cards": {before["id"]: "legacy-hash"}},
            source_result={
                "behavior_categories": [
                    {
                        "behavior": "Authentication",
                        "conclusion": "Denied; later actions not inspected",
                        "check_ids": [check["id"]],
                    }
                ]
            },
            artifact_ids=[check["id"]],
        ),
    )
    later = card_for(store, ds, 2, "Later observation", lead_ids=[lead["id"]])
    row = sl.aggregate(store)[0]
    assert len(row["checks"]) == 1
    assert row["checks"][0]["card_id"] == before["id"]
    assert row["checks"][0]["historical"] and not row["checks"][0]["current"]
    assert "Denied; later actions not inspected" in row["checks"][0]["conclusion"]
    assert any(later["id"] in gap for gap in row["gaps"])
