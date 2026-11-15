import copy
import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from irkit import board, events, integrity, report, telemetry
from irkit import source_leads as sl
from irkit.completion import assess, checkpoint
from irkit.datasets import publish_dataset, query_dataset, read_query_result, run_transform
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


def lead_for(store, ds, address="192.0.2.1", row=1):
    card = card_for(store, ds, row, title="Observation " + address)
    lead = sl.register_source_lead(
        store, address, "client", "exact", [card["id"]], "Potential administrative misuse", "direct_peer"
    )
    return lead, store.get(card["id"])


def start(store, lead):
    task = sl.plan_source_review(store, lead["id"], "All published audit partitions")
    return board.update_task(store, task["id"], task["revision"], "running")


def finish(store, task, ds):
    run = query_dataset(store, [ds["id"]], f"SELECT * FROM {ds['id']} WHERE client='192.0.2.1'")
    check = board.submit_check(
        store,
        "Review source branches",
        [run["id"]],
        "inconclusive",
        "Whole lab audit partition",
        "Application permission boundary unavailable; cannot establish unauthorized access",
        task_id=task["id"],
        body_claim="not_required",
        body_reason="Audit actions and results only",
    )
    updated = sl.complete_source_review(
        store,
        task["id"],
        [check["id"]],
        [
            dict(
                behavior="All recorded audit actions",
                conclusion="Actions observed; access rights unknown",
                check_ids=[check["id"]],
            )
        ],
        "No permission baseline",
        "inconclusive",
        "No claim of compromise",
    )
    return board.update_task(
        store,
        task["id"],
        updated["revision"],
        "completed",
        "Bounded source review",
        list(updated["source_result"]["artifact_revisions"]),
    )


def synth(store):
    t = board.create_task(store, "ir-synthesize", "Independent review", "All current evidence", [])
    return board.update_task(store, t["id"], t["revision"], "running")


def test_review_metadata_does_not_reopen_source_query(lab):
    store, ds, _ = lab
    lead, card = lead_for(store, ds)
    task = finish(store, start(store, lead), ds)
    review(store, task)
    before = sl.source_state(store, store.get(lead["id"]))["snapshot"]
    store.update(card["id"], {"review_state": "needs_review"})
    assert not sl.source_state(store, store.get(lead["id"]))["complete"]
    reviewer = synth(store)
    card = store.get(card["id"])
    integrity.resolve_review(
        store, card["id"], card["revision"], "retain", "Facts and evidence are unchanged", reviewer["id"]
    )
    after = sl.source_state(store, store.get(lead["id"]))
    assert after["snapshot"] == before
    assert after["complete"]


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


def review(store, task, synthesis=None):
    synthesis = synthesis or synth(store)
    return sl.review_source_task(
        store,
        task["id"],
        synthesis["id"],
        "supported",
        "Queries and raw audit checked; permissions gap is real",
    )


def test_registration_merge_auto_updates_and_preserves_history(lab):
    store, ds, _ = lab
    lead, card = lead_for(store, ds)
    again = sl.register_source_lead(
        store,
        lead["address"],
        "client",
        "exact",
        [card["id"]],
        "Potential administrative misuse",
        "direct_peer",
    )
    assert again["id"] == lead["id"] and len(list(store.all("source_lead"))) == 1
    newer = card_for(store, ds, 3, "Setting change", lead_ids=[lead["id"]])
    lead = store.get(lead["id"])
    assert set(lead["cards"]) == {card["id"], newer["id"]}
    assert lead["judgment"] == "suspected"
    before = sl.source_snapshot(store, lead)
    event = copy.deepcopy(newer["event"])
    event["title"] = "Clearer title"
    revised = events.revise_event(store, newer["id"], newer["revision"], event, [], "Wording only")
    lead = store.get(lead["id"])
    assert lead["cards"][newer["id"]]["revision"] == revised["revision"]
    assert sl.source_snapshot(store, lead) == before
    event = copy.deepcopy(revised["event"])
    event["observed"] = "Corrected recorded outcome"
    revised = events.revise_event(
        store, revised["id"], revised["revision"], event, [], "Corrected observation"
    )
    assert sl.source_snapshot(store, store.get(lead["id"])) != before
    event = copy.deepcopy(revised["event"])
    event["source_lead_ids"] = []
    events.revise_event(store, revised["id"], revised["revision"], event, [], "Attribution withdrawn")
    assert not store.get(lead["id"])["cards"][newer["id"]]["linked"]
    assert integrity.history(store, lead["id"])["items"]


def test_parallel_assignment_deduplicates_and_preserves_snapshot(lab):
    store, ds, _ = lab
    lead, card = lead_for(store, ds)
    with ThreadPoolExecutor(max_workers=2) as pool:
        tasks = list(
            pool.map(lambda _: sl.plan_source_review(store, lead["id"], "All available records"), range(2))
        )
    assert tasks[0]["id"] == tasks[1]["id"]
    task = board.update_task(store, tasks[0]["id"], tasks[0]["revision"], "running")
    frozen = copy.deepcopy(task["source_snapshot"])
    newer = card_for(store, ds, 3, "Concurrent discovery", [lead["id"]])
    assert store.get(task["id"])["source_snapshot"] == frozen
    task = finish(store, task, ds)
    review(store, task)
    state = sl.source_state(store, store.get(lead["id"]))
    assert state["state"] == "needs_incremental" and state["missing_card_ids"] == [newer["id"]]
    delta = sl.plan_source_review(store, lead["id"], "New branch only")
    assert delta["id"] != task["id"] and delta["source_delta_card_ids"] == [newer["id"]]
    delta = board.update_task(store, delta["id"], delta["revision"], "running")
    delta = finish(store, delta, ds)
    review(store, delta)
    assert sl.source_state(store, store.get(lead["id"]))["complete"]


def test_completion_requires_real_coverage_and_independent_review(lab):
    store, ds, _ = lab
    lead, _ = lead_for(store, ds)
    task = start(store, lead)
    with pytest.raises(ValueError, match="SOURCE_RESULT_MISSING"):
        board.update_task(
            store, task["id"], task["revision"], "completed", "Claimed done", [next(store.all("card"))["id"]]
        )
    check = board.submit_check(
        store, "Not queried", [], "inconclusive", "lab", "Not yet checked", task_id=task["id"]
    )
    with pytest.raises(ValueError, match="actual queries"):
        sl.complete_source_review(
            store,
            task["id"],
            [check["id"]],
            [dict(behavior="unknown", conclusion="unknown", check_ids=[check["id"]])],
            "Unknown",
            "inconclusive",
            "Unknown",
        )
    task = finish(store, task, ds)
    assert sl.source_state(store, store.get(lead["id"]))["state"] == "awaiting_review"
    assert "SOURCE_REVIEW_PENDING" in {i["code"] for i in closure_readiness(store)["issues"]}
    with pytest.raises(ValueError, match="independent"):
        sl.review_source_task(store, task["id"], task["id"], "supported", "Self approved")
    review(store, task)
    assert closure_readiness(store)["ready"]


def test_new_own_events_are_in_result_but_title_change_does_not_requery(lab):
    store, ds, _ = lab
    lead, _ = lead_for(store, ds)
    task = start(store, lead)
    card = card_for(store, ds, 4, "Additional operation", [lead["id"]], task)
    task = finish(store, task, ds)
    review(store, task)
    assert sl.source_state(store, store.get(lead["id"]))["complete"]
    e = copy.deepcopy(card["event"])
    e["title"] = "Readable operation title"
    events.revise_event(store, card["id"], card["revision"], e, [], "Title only")
    assert sl.source_state(store, store.get(lead["id"]))["complete"]


def test_source_queries_exact_match_and_batch_without_known_paths(lab):
    store, ds, _ = lab
    a, _ = lead_for(store, ds)
    b, _ = lead_for(store, ds, "192.0.2.10", 2)
    run = sl.source_behavior_overview(store, [a["id"]], [ds["id"]], ["action", "status"], "event_time")
    assert run["status"] == "succeeded"
    rows = read_query_result(store, run["id"])["rows"]
    assert sum(r["record_count"] for r in rows) == 3
    assert {r["action"] for r in rows} == {"authenticate", "change_setting", "export"}
    batch = sl.source_behavior_overview(store, [a["id"], b["id"]], [ds["id"]], ["action"])
    assert sum(r["record_count"] for r in read_query_result(store, batch["id"])["rows"]) == 4
    truncated = sl.source_behavior_overview(store, [a["id"]], [ds["id"]], ["action"], max_rows=1)
    assert truncated["truncated"]
    with pytest.raises(ValueError, match="Fields"):
        sl.source_behavior_overview(store, [a["id"]], [ds["id"]], ["missing_column"])


def test_review_rejection_creates_new_task_and_unknown_sources_do_not_leak(lab):
    store, ds, _ = lab
    lead, _ = lead_for(store, ds)
    task = finish(store, start(store, lead), ds)
    s = synth(store)
    sl.review_source_task(
        store, task["id"], s["id"], "needs_more_evidence", "Inspect unexplained export branch"
    )
    nxt = sl.plan_source_review(store, lead["id"], "Export branch")
    assert nxt["id"] != task["id"]
    with pytest.raises(ValueError):
        sl.register_source_lead(store, "not an IP", "client", "exact", [], "Unknown")
    with pytest.raises(ValueError, match="Unknown source_lead"):
        event, ref = event_for(ds, 1, lead_ids=["source_lead_foreign"])
        events.validate(store, event)
    row = next(o for o in snapshot(store)["objects"] if o["id"] == lead["id"])
    assert row["investigation"]["state"] == "assigned"


def test_native_parallel_workers_cannot_finish_with_one_outstanding(lab):
    store, ds, _ = lab
    a, _ = lead_for(store, ds)
    b, _ = lead_for(store, ds, "192.0.2.10", 2)
    telemetry.initialize(store)
    base = checkpoint(store)
    one = start(store, a)
    two = start(store, b)
    for i, t in enumerate([one, two]):
        telemetry.record(
            store,
            "parallel",
            dict(
                type="assistant",
                message=dict(
                    content=[
                        dict(
                            type="tool_use",
                            id=f"child{i}",
                            name="Agent",
                            input=dict(
                                subagent_type="ir-investigate", prompt=t["id"], run_in_background=False
                            ),
                        )
                    ]
                ),
            ),
        )
    finish(store, one, ds)
    telemetry.record(store, "parallel", dict(type="result", is_error=False))
    result = assess(store, **base)
    assert result["status"] == "incomplete" and two["id"] in result["unfinished_task_ids"]


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


def test_five_chapter_final_requires_current_citations_and_source_closure(lab):
    store, ds, _ = lab
    lead, card = lead_for(store, ds)
    with pytest.raises(ValueError, match="SOURCE_REVIEW_PENDING"):
        report.render_report(store, "Premature", [], [], report_content=content(card))
    task = finish(store, start(store, lead), ds)
    s = synth(store)
    review(store, task, s)
    card = store.get(card["id"])
    integrity.review_delivery(
        store,
        s["id"],
        {c["id"]: "Raw audit and limits checked" for c in store.all("card")},
        "No cross-environment attribution",
    )
    with pytest.raises(ValueError, match="structured report_content"):
        report.render_report(store, "No structured content", [], [])
    wrong = content(card)
    wrong["conclusions"][0]["evidence"][0]["revision"] = 1
    with pytest.raises(ValueError, match="current"):
        report.render_report(store, "Wrong version", [], [], report_content=wrong)
    result = report.render_report(
        store, "Bounded result", ["Permission baseline missing"], [], report_content=content(card)
    )
    text = store.path(result["path"]).read_text()
    assert [line for line in text.splitlines() if line.startswith("## ")][:5] == [
        "## 1. 事件背景与调查范围",
        "## 2. 事件结论与影响评估",
        "## 3. 攻击时间线与攻击路径",
        "## 4. 攻击来源与具体行为",
        "## 5. 证据缺口与处置建议",
    ]
    assert result["template_version"] == 1 and result["evidence_labels"][card["id"]] == "E-001"
    card_for(store, ds, 4, "New source event after report", [lead["id"]])
    assert store.get(result["id"])["status"] == "stale"
    assert not closure_readiness(store)["ready"]


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


def test_withdrawal_and_rejected_review_reopen_scope(lab):
    store, ds, _ = lab
    lead, card = lead_for(store, ds)
    task = finish(store, start(store, lead), ds)
    s = synth(store)
    review(store, task, s)
    assert sl.source_state(store, store.get(lead["id"]))["complete"]
    e = copy.deepcopy(card["event"])
    e["source_lead_ids"] = []
    events.revise_event(store, card["id"], card["revision"], e, [], "Corrected attribution: shared exit")
    assert not sl.source_state(store, store.get(lead["id"]))["complete"]
    delta = finish(store, start(store, lead), ds)
    review(store, delta, s)
    assert sl.source_state(store, store.get(lead["id"]))["complete"]
    sl.review_source_task(
        store, delta["id"], s["id"], "needs_more_evidence", "New counterevidence needs inspection"
    )
    assert not sl.source_state(store, store.get(lead["id"]))["complete"]
    assert sl.plan_source_review(store, lead["id"], "Check counterevidence")["id"] != delta["id"]


def test_new_partition_reopens_review_and_stale_check_is_not_valid(lab):
    store, ds, _ = lab
    lead, _ = lead_for(store, ds)
    task = finish(store, start(store, lead), ds)
    review(store, task)
    clone = {k: v for k, v in ds.items() if k not in ("id", "kind", "revision")}
    store.put("dataset", clone)
    state = sl.source_state(store, store.get(lead["id"]))
    assert not state["complete"]
    new = sl.plan_source_review(store, lead["id"], "Include new partition")
    assert len(new["source_snapshot"]["datasets"]) == 2
    store.update(task["source_result"]["check_ids"][0], {"limitations": "Corrected scope"})
    assert not sl.result_current(store, store.get(task["id"]))


def test_mcp_schema_and_role_tool_boundaries(lab):
    import asyncio

    from irkit.mcpserver import build_server
    from irkit.templates import MAIN, ROLE_TOOLS

    store, _, _ = lab
    schema = {t.name: t.inputSchema for t in asyncio.run(build_server(store.root).list_tools())}
    assert {
        "register_source_lead",
        "source_queue",
        "plan_source_review",
        "complete_source_review",
        "review_source_task",
    } <= schema.keys()
    assert "report_content" in schema["render_report"]["properties"]
    assert "plan_source_review" not in ROLE_TOOLS["ir-investigate"]
    assert "review_source_task" not in ROLE_TOOLS["ir-investigate"]
    assert "review_source_task" in ROLE_TOOLS["ir-synthesize"]
    assert all(not t.startswith("Agent") for tools in ROLE_TOOLS.values() for t in tools)
    assert "两个不同 task_id" in MAIN


def test_obsolete_source_checks_do_not_block_reviewed_replacement(lab):
    store, ds, _ = lab
    lead, _ = lead_for(store, ds)
    old = finish(store, start(store, lead), ds)
    review(store, old)
    check_id = old["source_result"]["check_ids"][0]
    store.update(check_id, {"status": "stale", "stale_because": "synthetic prior interpretation corrected"})
    assert not closure_readiness(store)["ready"]
    replacement = finish(store, start(store, lead), ds)
    review(store, replacement)
    assert sl.source_state(store, store.get(lead["id"]))["complete"]
    assert closure_readiness(store)["ready"]
    assert store.get(check_id)["status"] == "stale"


def test_report_timeline_sorts_known_offsets_and_keeps_unknown_last(lab):
    from irkit.report_template import event_order

    rows = [
        dict(id="a", time_range="2026-01-01T09:00:00+08:00"),
        dict(id="b", time_range="2026-01-01T00:30:00Z"),
        dict(id="c", time_range="unknown"),
    ]
    assert [r["id"] for r in sorted(rows, key=event_order)] == ["b", "a", "c"]


def test_forwarded_source_keeps_distinct_trust_and_exact_first_hop(lab):
    store, ds, _ = lab
    lead, card = lead_for(store, ds)
    forwarded = sl.register_source_lead(
        store, "192.0.2.1", "forwarded", "forwarded_first", [card["id"]], "Unverified forwarded claim"
    )
    assert forwarded["id"] != lead["id"] and forwarded["attribution"] == "unverified"
    run = sl.source_behavior_overview(store, [forwarded["id"]], [ds["id"]], ["action"])
    assert sum(r["record_count"] for r in read_query_result(store, run["id"])["rows"]) == 3
    with pytest.raises(ValueError, match="same field"):
        sl.source_behavior_overview(store, [lead["id"], forwarded["id"]], [ds["id"]], ["action"])


def test_incremental_review_reuses_baseline_but_requires_new_query(lab):
    store, ds, _ = lab
    lead, _ = lead_for(store, ds)
    clone = store.put("dataset", {k: v for k, v in ds.items() if k not in ("id", "kind", "revision")})
    task = start(store, lead)
    run = query_dataset(
        store, [ds["id"], clone["id"]], "SELECT _dataset_id,COUNT(*) FROM ir_all_events GROUP BY _dataset_id"
    )
    check = board.submit_check(
        store,
        "Baseline across both partitions",
        [run["id"]],
        "inconclusive",
        "Both partitions",
        "Fixture baseline; not full semantic inspection",
        task_id=task["id"],
    )
    task = sl.complete_source_review(
        store,
        task["id"],
        [check["id"]],
        [dict(behavior="baseline", conclusion="No unbounded claims", check_ids=[check["id"]])],
        "Permission baseline absent",
        "inconclusive",
        "Bounded test",
    )
    task = board.update_task(
        store, task["id"], task["revision"], "completed", "Baseline checked", [check["id"]]
    )
    review(store, task)
    card_for(store, ds, 3, "New operation", [lead["id"]])
    delta = start(store, lead)
    assert delta["source_base_checks"] == {check["id"]: check["revision"]}
    # This round queries only the changed partition; the other immutable partition reuses its baseline.
    delta = finish(store, delta, ds)
    assert delta["source_result"]["inherited_check_ids"] == [check["id"]]
    review(store, delta)
    assert sl.source_state(store, store.get(lead["id"]))["complete"]
    store.update(check["id"], {"limitations": "Baseline correction"})
    assert not sl.result_current(store, store.get(delta["id"]))


def test_fresh_investigation_has_no_prior_source_judgment(lab):
    from irkit.cases import fresh_investigation

    store, ds, _ = lab
    lead, _ = lead_for(store, ds)
    fresh = fresh_investigation(store, "Independent analysis")
    assert not list(fresh.all("source_lead")) and not list(fresh.all("task"))
    with pytest.raises(ValueError, match="Unknown source_lead"):
        sl.plan_source_review(fresh, lead["id"], "Forbidden inherited source")


def test_source_review_can_cite_existing_hits_without_duplicate_cards(lab):
    store, ds, _ = lab
    lead, card = lead_for(store, ds)
    task = start(store, lead)
    query = query_dataset(store, [ds["id"]], f"SELECT * FROM {ds['id']} WHERE client='192.0.2.1'")
    check = board.submit_check(
        store,
        "Review known behavior",
        [query["id"]],
        "hits",
        "All audit rows",
        "Previously observed action is present",
        task_id=task["id"],
        body_claim="not_required",
        body_reason="Audit metadata",
    )
    result = sl.complete_source_review(
        store,
        task["id"],
        [check["id"]],
        [
            {
                "behavior": "Observed action",
                "conclusion": "Same evidenced event, no duplicate",
                "check_ids": [check["id"]],
            }
        ],
        "No identity baseline",
        "inconclusive",
        "Existing event independently queried",
        [card["id"]],
    )
    assert result["source_result"]["finding_card_ids"] == [card["id"]]
    assert len(list(store.all("card"))) == 1
    completed = board.update_task(
        store,
        task["id"],
        result["revision"],
        "completed",
        "Existing observation checked",
        list(result["source_result"]["artifact_revisions"]),
    )
    review(store, completed)
    assert sl.source_state(store, store.get(lead["id"]))["complete"]
