import copy
import json

import pytest

from irkit import board, events, integrity, report
from irkit.datasets import publish_dataset, query_dataset, run_transform
from irkit.evidence import initialize_case
from irkit.verification import closure_readiness


@pytest.fixture
def audit(tmp_path):
    logs = tmp_path / "audit"
    logs.mkdir()
    records = [
        dict(
            time="2026-01-01T00:00:00Z",
            host="node-a",
            environment="lab",
            subject="operator",
            object="account-x",
            action="authenticate",
            state="denied",
            path="/session",
            size=10,
        ),
        dict(
            time="2026-01-01T00:00:01Z",
            host="node-a",
            environment="lab",
            subject="operator",
            object="account-x",
            action="credential_change",
            state="accepted",
            path="/settings",
            size=20,
        ),
        dict(
            time="2026-01-01T00:00:02Z",
            host="node-a",
            environment="lab",
            subject="operator",
            object="account-x",
            action="authenticate",
            state="accepted",
            path="/session",
            size=30,
        ),
        dict(
            time="2026-01-01T00:00:03Z",
            host="node-b",
            environment="live",
            subject="operator",
            object="account-x",
            action="authenticate",
            state="denied",
            path="/session",
            size=10,
        ),
    ]
    (logs / "audit.jsonl").write_text("\n".join(json.dumps(r) for r in records) + "\n")
    case = initialize_case(logs, tmp_path / "cases", "Synthetic generic state changes")
    sid = case.list("source")[0]["id"]
    run = run_transform(
        case,
        [sid],
        f"""import json
for n,line in records({sid!r}):
    emit(json.loads(line), [{{"source_id":{sid!r},"start":n,"end":n}}])
""",
    )
    ds = publish_dataset(
        case,
        run["id"],
        "Generic audit",
        {"time": "UTC", "state": "recorded application outcome"},
        "4/4 synthetic rows",
        ["SELECT count(*) FROM {dataset_id}"],
    )
    return case, sid, ds


def synth(case):
    t = board.create_task(case, "ir-synthesize", "Review evidence", "Fixture", [])
    return board.update_task(case, t["id"], t["revision"], "running")


def evt(ref, key="attempt", observed="An authentication attempt was denied."):
    q = dict(
        question="",
        priority="optional",
        status="not_applicable",
        reason="Synthetic scoped test",
        check_ids=[],
    )
    return dict(
        title="Authentication result",
        environment="lab",
        asset="node-a",
        observed=observed,
        possible_causes=[],
        observed_effects=[],
        potential_impacts=[],
        upstream=q,
        downstream=copy.deepcopy(q),
        claims=[
            dict(
                key=key,
                statement=observed,
                level="response",
                evidence=[ref],
                scope=dict(environment="lab", dimensions={"host": ["node-a"]}),
            )
        ],
    )


def test_revision_preserves_evidence_and_distinct_claims(audit):
    case, sid, ds = audit
    r1 = {"source_id": sid, "start": 1, "end": 1}
    r2 = {"source_id": sid, "start": 2, "end": 2}
    t = synth(case)
    card = events.submit_event(case, evt(r1), [r1], "UTC", t["id"])
    changed = evt(r2, "change", "A credential change was submitted.")
    updated = events.revise_event(case, card["id"], 1, changed, [r2], "Add the intervening state change")
    assert updated["evidence"] == [r1, r2]
    assert {c["key"] for c in updated["event"]["claims"]} == {"attempt", "change"}
    with pytest.raises(ValueError, match="retained claim"):
        events.revise_event(case, card["id"], 2, changed, [r2], "Remove wrong anchor", remove_evidence=[r1])
    retired = events.revise_event(
        case,
        card["id"],
        2,
        changed,
        [r2],
        "Correction with explicit withdrawal",
        remove_evidence=[r1],
        remove_claims={"attempt": "Different subject; no longer supports this event"},
    )
    assert retired["evidence"] == [r2] and retired["retired_claims"][0]["claim"]["evidence"] == [r1]
    assert integrity.history(case, card["id"])["items"][0]["evidence_removed"] == [r1]
    with pytest.raises(ValueError, match="Revision conflict"):
        events.revise_event(case, card["id"], 2, changed, [r2], "Stale writer")


def test_premise_revision_keeps_facts_and_blocks_omitted_cards_and_links(audit):
    case, sid, ds = audit
    r = {"source_id": sid, "start": 1, "end": 1}
    a = board.submit_card(case, "Initial premise", "observation", [r])
    b = board.submit_card(case, "Independent observed event", "observation", [r], depends_on=[a["id"]])
    link = board.submit_link(case, a["id"], b["id"], "Possible prerequisite", [r])
    board.revise_card(case, a["id"], 1, "Corrected premise", [r], "Time correction")
    assert case.get(b["id"])["status"] == "candidate"
    assert case.get(b["id"])["review_state"] == "needs_review"
    assert case.get(link["id"])["review_state"] == "needs_review"
    assert not closure_readiness(case)["ready"]
    t = synth(case)
    b = case.get(b["id"])
    integrity.resolve_review(
        case, b["id"], b["revision"], "retain", "Original event independently verified", t["id"]
    )
    link = case.get(link["id"])
    integrity.resolve_review(
        case, link["id"], link["revision"], "withdraw", "Corrected timing refutes prerequisite", t["id"]
    )
    assert closure_readiness(case)["ready"]
    assert case.get(link["id"])["disposition"]["decision"] == "withdraw"


def test_merge_requires_migrating_unique_facts_not_just_same_evidence(audit):
    case, sid, ds = audit
    t = synth(case)
    r = {"source_id": sid, "start": 1, "end": 1}
    a = events.submit_event(case, evt(r), [r], "t1", t["id"])
    b = events.submit_event(case, evt(r, "other", "Different observation"), [r], "t2", t["id"])
    with pytest.raises(ValueError, match="each distinct claim"):
        integrity.resolve_review(case, a["id"], 1, "merge", "Deduplicate", t["id"], [b["id"]])
    payload = copy.deepcopy(b["event"])
    payload["claims"] += a["event"]["claims"]
    b = events.revise_event(case, b["id"], b["revision"], payload, [r], "Migrate unique finding")
    a = integrity.resolve_review(
        case, a["id"], 1, "merge", "Original findings retained at target", t["id"], [b["id"]]
    )
    assert a["status"] == "superseded" and a["disposition"]["target_ids"] == [b["id"]]


def test_question_only_revision_does_not_invalidate_observations_or_followup(audit):
    case, sid, ds = audit
    t = synth(case)
    r = {"source_id": sid, "start": 1, "end": 1}
    a = events.submit_event(case, evt(r), [r], "t", t["id"])
    b = board.submit_card(case, "Observed after a", "observation", [r], depends_on=[a["id"]])
    f = board.create_task(case, "ir-investigate", "Check outcome", "Fixture", [ds["id"]], a["id"])
    payload = copy.deepcopy(a["event"])
    payload["downstream"]["reason"] = "This fixture only establishes the recorded state"
    a = events.revise_event(case, a["id"], 1, payload, [r], "Clarify visibility boundary only")
    assert not integrity.pending(case.get(b["id"]))
    assert not integrity.parent_changed(f, a)


def test_trace_keeps_failure_change_retry_and_environment_scope(audit):
    case, sid, ds = audit
    run = integrity.trace_events(
        case,
        [ds["id"]],
        {"host": ["node-a"], "object": ["account-x"]},
        "time",
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:03Z",
        ["action", "object"],
        "state",
    )
    assert run["status"] == "succeeded" and not run["truncated"]
    assert [r["state"] for r in run["preview"]] == ["denied", "accepted", "accepted"]
    assert [r["action"] for r in run["preview"]] == ["authenticate", "credential_change", "authenticate"]
    assert all(r["_refs"][0]["source_id"] == sid for r in run["preview"])
    limited = integrity.trace_events(
        case,
        [ds["id"]],
        {"host": ["node-a"]},
        "time",
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:03Z",
        ["action"],
        "state",
        1,
    )
    assert limited["truncated"]
    with pytest.raises(ValueError, match="real schema"):
        integrity.trace_events(
            case,
            [ds["id"]],
            {"host; DROP TABLE events": ["x"]},
            "time",
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:03Z",
            [],
            "state",
        )


def test_claim_scope_checks_raw_host_time_and_environment(audit):
    case, sid, ds = audit
    r = {"source_id": sid, "start": 4, "end": 4}
    with pytest.raises(ValueError, match="Scope mismatch"):
        events.validate(case, evt(r))
    e = evt({"source_id": sid, "start": 1, "end": 1})
    e["claims"][0]["scope"].update(
        time_field="time", time_from="2026-01-02T00:00:00Z", time_to="2026-01-03T00:00:00Z"
    )
    with pytest.raises(ValueError, match="outside"):
        events.validate(case, e)
    e = evt({"source_id": sid, "start": 1, "end": 1})
    e["environment"] = "live"
    with pytest.raises(ValueError, match="environment must match"):
        events.validate(case, e)


def test_statistic_uses_actual_result_cell_and_requires_scope_projection(audit):
    case, sid, ds = audit
    run = query_dataset(
        case,
        [ds["id"]],
        "SELECT host, count(*) AS requests, sum(size) AS bytes FROM ir_all_events GROUP BY host ORDER BY host",
    )
    e = evt({"source_id": sid, "start": 1, "end": 1})
    c = e["claims"][0]
    c["evidence"] = [{"query_id": run["id"]}]
    c["statistic"] = dict(
        query_id=run["id"],
        row=0,
        column="bytes",
        unit="bytes",
        population="All recorded actions on this host",
    )
    validated = events.validate(case, e)["claims"][0]["statistic_snapshot"]
    assert validated["value"] == 60 and validated["result_row"]["requests"] == 3
    c["scope"]["dimensions"]["path"] = ["/session"]
    with pytest.raises(ValueError, match="not projected"):
        events.validate(case, e)
    c["scope"]["dimensions"] = {"host": ["node-b"]}
    with pytest.raises(ValueError, match="Scope mismatch"):
        events.validate(case, e)
    c["scope"]["dimensions"] = {"host": ["node-a"]}
    c["statistic"]["value"] = 999
    with pytest.raises(ValueError, match="tool-derived"):
        events.validate(case, e)


def test_new_delivery_requires_review_and_retains_all_claims(audit):
    case, sid, ds = audit
    t = board.create_task(case, "ir-synthesize", "Review", "Fixture", [], event_policy_version=2)
    t = board.update_task(case, t["id"], t["revision"], "running")
    r = {"source_id": sid, "start": 1, "end": 1}
    card = events.submit_event(case, evt(r), [r], "UTC", t["id"])
    with pytest.raises(ValueError, match="DELIVERY_UNREVIEWED"):
        report.render_report(case, "Bounded observation", [], [])
    integrity.review_delivery(
        case,
        t["id"],
        {card["id"]: "Raw outcome verified; same asset and no execution inference"},
        "Environment and claim scope verified",
    )
    out = report.render_report(case, "Bounded observation", [], [])
    text = case.path(out["path"]).read_text()
    assert card["id"] not in text
    assert any(c["key"] == "attempt" for c in case.get(card["id"])["event"]["claims"])
    assert {"id": card["id"], "revision": card["revision"]} in out["snapshot"]
    card = events.revise_event(case, card["id"], card["revision"], evt(r), [r], "Review explanation updated")
    with pytest.raises(ValueError, match="DELIVERY_UNREVIEWED"):
        report.render_report(case, "Bounded observation", [], [])
    assert report.render_report(case, "Pending review", [], [], delivery="progress")["delivery"] == "progress"


def test_environment_conflict_blocks_final_even_without_task_artifact_reference(audit):
    case, sid, ds = audit
    t = synth(case)
    r = {"source_id": sid, "start": 1, "end": 1}
    events.submit_event(case, evt(r), [r], "t1", t["id"])
    other = evt(r)
    other["environment"] = "live"
    other["claims"][0]["scope"]["environment"] = "live"
    events.submit_event(case, other, [r], "t2", t["id"])
    assert any(i["code"] == "ENVIRONMENT_CONFLICT" for i in closure_readiness(case)["issues"])


def test_explicit_disposition_of_delivered_artifact_can_close_without_erasing_it(audit):
    from irkit.verification import task_readiness

    case, sid, ds = audit
    t = board.create_task(case, "ir-investigate", "Review changes", "Fixture", [ds["id"]])
    t = board.update_task(case, t["id"], 1, "running")
    ref = {"source_id": sid, "start": 1, "end": 1}
    a = board.submit_card(case, "Observed state", "observation", [ref], task_id=t["id"])
    b = board.submit_card(
        case, "Initially inferred relationship", "inference", [ref], depends_on=[a["id"]], task_id=t["id"]
    )
    board.update_task(case, t["id"], t["revision"], "completed", "Initial analysis", [a["id"], b["id"]])
    board.revise_card(case, a["id"], 1, "Corrected recorded state", [ref], "Corrected interpretation")
    reviewer = synth(case)
    b = case.get(b["id"])
    integrity.resolve_review(
        case, b["id"], b["revision"], "withdraw", "Changed premise refutes the inference", reviewer["id"]
    )
    assert task_readiness(case, t["id"])["ready"]
    assert closure_readiness(case)["ready"]
    assert case.get(b["id"])["evidence"] == [ref]


def test_claims_required_by_new_runtime_policy_and_mcp_schema(audit):
    import asyncio

    from irkit.mcpserver import build_server

    case, sid, ds = audit
    t = board.create_task(
        case, "ir-investigate", "Investigate", "Fixture", [ds["id"]], event_policy_version=2
    )
    t = board.update_task(case, t["id"], 1, "running")
    ref = {"source_id": sid, "start": 1, "end": 1}
    e = evt(ref)
    e.pop("claims")
    with pytest.raises(ValueError, match="atomic claims"):
        events.submit_event(case, e, [ref], "UTC", t["id"])
    server = build_server(case.root)
    tools = asyncio.run(server.list_tools())
    names = {t.name for t in tools}
    assert {"trace_events", "object_history", "resolve_review", "review_delivery"}.issubset(names)
    spec = next(t for t in tools if t.name == "revise_event").inputSchema
    assert "remove_evidence" in spec["properties"] and "remove_claims" in spec["properties"]


def test_history_api_and_frontend_assets(audit):
    import threading
    import urllib.request

    from irkit.web import create_server

    case, sid, ds = audit
    ref = {"source_id": sid, "start": 1, "end": 1}
    card = board.submit_card(case, "Original event", "observation", [ref])
    for _ in range(12):
        card = board.revise_card(
            case, card["id"], card["revision"], "Original event", [ref], "Clarify evidence"
        )
    server = create_server(case.root, 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:

        def get(path):
            with urllib.request.urlopen(base + path) as response:
                return response.read()

        obj = json.loads(get("/api/object?id=" + card["id"]))
        assert len(obj["history"]["items"]) == 10 and obj["history"]["next_offset"] == 10
        older = json.loads(get("/api/object-history?id=" + card["id"] + "&offset=10"))
        assert len(older["items"]) == 3 and older["next_offset"] is None
        assert b"integrityHTML" in get("/events.js")
        assert b"data-history" in get("/app.js")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
