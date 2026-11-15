"""Case-local source index and bounded review tasks. No model scheduling or identity attribution."""

import hashlib
import ipaddress
import json

from .integrity import pending
from .store import dumps, now

INVALID = {"stale", "rejected", "superseded"}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def objects(store, kind, con):
    return [
        store.get(r[0], con=con)
        for r in con.execute("SELECT id FROM objects WHERE kind=? ORDER BY created,id", (kind,)).fetchall()
    ]


def require_text(value, name):
    if not isinstance(value, str) or not value.strip() or len(value) > 4000:
        raise ValueError(f"{name}: nonempty text <=4000 required")
    return value.strip()


def card_entry(card):
    event = card.get("event", {})
    # Titles, wording of investigation questions and model hypotheses do not reopen source coverage.
    facts = {k: event.get(k) for k in ("environment", "asset", "observed", "observed_effects", "claims")}
    return dict(
        id=card["id"],
        revision=card["revision"],
        title=event.get("title", card["statement"][:160]),
        environment=event.get("environment", "unknown"),
        asset=event.get("asset", "unknown"),
        time_range=card.get("time_range", "unknown"),
        status=card["status"],
        review_state=card.get("review_state", "legacy"),
        fingerprint=digest(
            [
                facts,
                card["evidence"],
                card.get("time_range"),
                card["status"] in INVALID,
                card.get("disposition") if card.get("status") in INVALID else None,
            ]
        ),
    )


def sync_card(store, card, con):
    """Called within the same transaction as a card write; all projections remain recoverable."""
    declared = set(card.get("event", {}).get("source_lead_ids", []))
    for lid in declared:
        store.get(lid, "source_lead", con)
    for lead in objects(store, "source_lead", con):
        entries = dict(lead.get("cards", {}))
        if lead["id"] not in declared and card["id"] not in entries:
            continue
        entry = card_entry(card)
        entry["linked"] = lead["id"] in declared
        if entries.get(card["id"]) == entry:
            continue
        entries[card["id"]] = entry
        store.update(
            lead["id"],
            {
                "cards": entries,
                "revision_reason": f"同步关联事件 {card['id']} r{card['revision']}；关联状态 {entry['linked']}",
            },
            con=con,
            invalidate=True,
        )


def register_source_lead(store, address, field, match_mode, card_ids, reason, attribution="unverified"):
    address = str(ipaddress.ip_address(address.strip()))
    field, reason = require_text(field, "field"), require_text(reason, "reason")
    if match_mode not in ("exact", "forwarded_first") or attribution not in (
        "direct_peer",
        "unverified",
        "trusted_proxy",
    ):
        raise ValueError("Use exact/forwarded_first and direct_peer/unverified/trusted_proxy")
    if not isinstance(card_ids, list) or not 1 <= len(card_ids) <= 50:
        raise ValueError("Link 1..50 evidence cards")
    key = digest([address, field, match_mode])
    with store.transaction() as con:
        cards = [store.get(cid, "card", con) for cid in dict.fromkeys(card_ids)]
        if any(not c.get("event") or c["status"] in INVALID for c in cards):
            raise ValueError("Source registration needs current structured events")
        lead = next((o for o in objects(store, "source_lead", con) if o["source_key"] == key), None)
        if lead is None:
            lead = store.put(
                "source_lead",
                dict(
                    address=address,
                    field=field,
                    match_mode=match_mode,
                    attribution=attribution,
                    source_key=key,
                    reason=reason,
                    judgment="suspected",
                    judgment_note="Not independently reviewed",
                    status="candidate",
                    cards={},
                    registrations=[],
                ),
                con=con,
            )
        registration = dict(card_ids=sorted(set(card_ids)), reason=reason, attribution=attribution)
        if registration not in lead["registrations"]:
            store.update(
                lead["id"],
                {
                    "registrations": [*lead["registrations"], registration],
                    "revision_reason": "追加来源登记依据：" + reason,
                },
                con=con,
            )
        for card in cards:
            ids = list(dict.fromkeys([*card["event"].get("source_lead_ids", []), lead["id"]]))
            if ids != card["event"].get("source_lead_ids", []):
                store.update(card["id"], {"event": {**card["event"], "source_lead_ids": ids}}, con=con)
        return store.get(lead["id"], con=con)


def source_snapshot(store, lead, con=None):
    datasets = objects(store, "dataset", con) if con else list(store.all("dataset"))
    # All published partitions are offered, not just the known malicious window.
    return dict(
        cards={
            cid: digest([e["fingerprint"], e.get("linked", False)])
            for cid, e in lead.get("cards", {}).items()
        },
        datasets={
            d["id"]: digest([d["revision"], d.get("path"), d["status"]])
            for d in datasets
            if d["status"] not in INVALID
        },
    )


def result_current(store, task):
    result = task.get("source_result")
    if not result or task["status"] != "completed":
        return False
    for oid, revision in result["artifact_revisions"].items():
        obj = store.get(oid)
        unchanged_card = (
            obj["kind"] == "card"
            and result.get("card_fingerprints", {}).get(oid) == card_entry(obj)["fingerprint"]
        )
        if (
            (obj["revision"] != revision and not unchanged_card)
            or obj.get("status") in INVALID
            or pending(obj)
        ):
            return False
    return True


def source_state(store, lead, tasks=None):
    tasks = [
        t
        for t in (tasks if tasks is not None else store.all("task"))
        if t.get("source_lead_id") == lead["id"]
    ]
    current = source_snapshot(store, lead)
    pending_cards = [
        cid for cid, e in lead.get("cards", {}).items() if e.get("linked") and pending(store.get(cid))
    ]
    valid = [t for t in tasks if result_current(store, t)]
    covered = {}
    reviewers = []
    for t in valid:
        r = t["source_result"]
        if r["snapshot"]["datasets"] != current["datasets"]:
            continue
        review = t.get("source_review", {})
        reviewer = store.get(review["synthesis_task_id"], "task") if review else None
        if review.get("verdict") == "needs_more_evidence":
            for cid in r["snapshot"]["cards"]:
                covered.pop(cid, None)
            continue
        if (
            review.get("result_hash") == digest(r)
            and review.get("verdict") == "supported"
            and reviewer
            and reviewer["status"] != "failed"
        ):
            covered.update(r["snapshot"]["cards"])
            reviewers.append(t["id"])
    missing = [cid for cid, value in current["cards"].items() if covered.get(cid) != value]
    active = [t for t in tasks if t["status"] != "completed"]
    awaiting = [
        t["id"]
        for t in valid
        if t["source_result"]["snapshot"]["datasets"] == current["datasets"]
        and any(t["source_result"]["snapshot"]["cards"].get(cid) == current["cards"][cid] for cid in missing)
        and t.get("source_review", {}).get("verdict") != "needs_more_evidence"
    ]
    state = (
        "running"
        if any(t["status"] == "running" for t in active)
        else "assigned"
        if active
        else "awaiting_review"
        if awaiting
        else "needs_incremental"
        if tasks and missing
        else "pending"
        if not tasks
        else "reviewed"
    )
    # Even an empty/detached index requires an explicit review of its withdrawal.
    if not missing and not reviewers:
        state = "pending" if not tasks else "awaiting_review" if valid else "needs_incremental"
    if pending_cards and state == "reviewed":
        state = "awaiting_review"
    return dict(
        state=state,
        missing_card_ids=missing,
        task_ids=[t["id"] for t in tasks],
        active_task_ids=[t["id"] for t in active],
        awaiting_review=awaiting,
        reviewed_task_ids=reviewers,
        snapshot=current,
        pending_card_ids=pending_cards,
        complete=not missing and bool(reviewers) and not active and not pending_cards,
    )


def source_queue(store, limit=30, offset=0):
    if not 1 <= limit <= 100 or offset < 0:
        raise ValueError("Invalid page")
    leads = list(store.all("source_lead"))
    tasks = list(store.all("task"))
    return dict(
        total=len(leads),
        items=[
            {**lead, "investigation": source_state(store, lead, tasks)}
            for lead in leads[offset : offset + limit]
        ],
        next_offset=offset + limit if offset + limit < len(leads) else None,
    )


def plan_source_review(store, lead_id, scope, question="Review all source behavior and unexplained branches"):
    scope, question = require_text(scope, "scope"), require_text(question, "question")
    with store.transaction() as con:
        lead = store.get(lead_id, "source_lead", con)
        previous = [t for t in objects(store, "task", con) if t.get("source_lead_id") == lead_id]
        active = next((t for t in previous if t["status"] != "completed"), None)
        if active:
            return active  # Concurrent callers cannot double-assign the same source.
        snap = source_snapshot(store, lead, con)
        if not snap["datasets"]:
            raise ValueError("No published datasets available for source review")
        # A snapshot is immutable once assigned. New facts become a delta after this task finishes.
        covered = {}
        base_checks = {}
        for t in previous:
            if t.get("source_review", {}).get("verdict") == "needs_more_evidence":
                for cid in t.get("source_result", {}).get("snapshot", {}).get("cards", {}):
                    covered.pop(cid, None)
                continue
            if (
                result_current(store, t)
                and t["source_result"]["snapshot"]["datasets"] == snap["datasets"]
                and t.get("source_review", {}).get("verdict") != "needs_more_evidence"
            ):
                covered.update(t["source_result"]["snapshot"]["cards"])
                for cid in t["source_result"]["check_ids"]:
                    base_checks[cid] = store.get(cid, "check", con)["revision"]
        delta = [cid for cid, h in snap["cards"].items() if covered.get(cid) != h]
        if previous and not delta and covered:
            return previous[-1]
        inputs = list(snap["datasets"]) + [lead_id] + list(snap["cards"])
        return store.put(
            "task",
            dict(
                role="ir-investigate",
                question=lead["address"] + " · " + question,
                scope=scope,
                input_ids=inputs,
                status="pending",
                summary="",
                artifact_ids=[],
                requires_body_check=False,
                evidence_policy_version=1,
                event_policy_version=3,
                source_lead_id=lead_id,
                source_snapshot=snap,
                source_delta_card_ids=delta,
                source_policy_version=1,
                source_base_checks=base_checks,
            ),
            dependencies=inputs,
            con=con,
        )


def complete_source_review(
    store, task_id, check_ids, behavior_categories, limitations, judgment, note, finding_card_ids=None
):
    from .board import active_investigation

    task = active_investigation(store, task_id)
    if not task.get("source_lead_id"):
        raise ValueError("Expected a source review task")
    if judgment not in ("suspected", "attack_evidenced", "excluded", "inconclusive"):
        raise ValueError("Unknown source judgment")
    limitations, note = require_text(limitations, "limitations"), require_text(note, "note")
    if not behavior_categories or len(behavior_categories) > 50:
        raise ValueError("Record 1..50 inspected behavior categories, including unresolved branches")
    for b in behavior_categories:
        if (
            set(b) != {"behavior", "conclusion", "check_ids"}
            or not b["check_ids"]
            or not set(b["check_ids"]).issubset(check_ids)
        ):
            raise ValueError("Each behavior needs conclusion and actual check_ids")
        require_text(b["behavior"], "behavior")
        require_text(b["conclusion"], "conclusion")
    checks = [store.get(cid, "check") for cid in dict.fromkeys(check_ids)]
    if not checks or any(c.get("task_id") != task_id or c["status"] in INVALID for c in checks):
        raise ValueError("Attach current checks from this task")
    queries = [store.get(q, "run") for c in checks for q in c["query_ids"]]
    successful = [q for q in queries if q["status"] == "succeeded"]
    if not successful:
        raise ValueError("Source review requires actual queries for this round, not only inherited coverage")
    inherited = []
    for cid, revision in task.get("source_base_checks", {}).items():
        check = store.get(cid, "check")
        if check["revision"] == revision and check["status"] not in INVALID:
            inherited.append(check)
    inherited_queries = [store.get(qid, "run") for c in inherited for qid in c["query_ids"]]
    successful += [q for q in inherited_queries if q["status"] == "succeeded"]
    if set(task["source_snapshot"]["datasets"]) - {did for q in successful for did in q["datasets"]}:
        raise ValueError(
            "Source review requires actual queries across all assigned datasets; record failures as unfinished"
        )
    cards = [
        c
        for c in store.all("card")
        if c.get("task_id") == task_id
        and task["source_lead_id"] in c.get("event", {}).get("source_lead_ids", [])
    ]
    existing = []
    for cid in dict.fromkeys(finding_card_ids or []):
        card = store.get(cid, "card")
        if card in cards:
            continue
        if (
            cid not in task["source_snapshot"]["cards"]
            or task["source_lead_id"] not in card.get("event", {}).get("source_lead_ids", [])
            or card["status"] in INVALID
            or pending(card)
        ):
            raise ValueError(
                "finding_card_ids must reference current linked events in the assigned source snapshot"
            )
        if digest([card_entry(card)["fingerprint"], True]) != task["source_snapshot"]["cards"][cid]:
            raise ValueError("Existing finding changed after assignment; replan incremental coverage")
        existing.append(card)
    if any(c["outcome"] == "hits" for c in checks) and not (cards or existing):
        raise ValueError(
            "Hits require a linked event card: submit new findings or pass existing assigned finding_card_ids; do not duplicate events or relabel observed hits as inconclusive"
        )
    snap = json.loads(dumps(task["source_snapshot"]))
    for card in cards:
        snap["cards"][card["id"]] = digest([card_entry(card)["fingerprint"], True])
    result = dict(
        snapshot=snap,
        check_ids=list(dict.fromkeys(check_ids)),
        behavior_categories=behavior_categories,
        limitations=limitations,
        judgment=judgment,
        note=note,
        artifact_revisions={o["id"]: o["revision"] for o in checks + cards + existing + inherited},
        finding_card_ids=[c["id"] for c in cards + existing],
        inherited_check_ids=[c["id"] for c in inherited],
        card_fingerprints={c["id"]: card_entry(c)["fingerprint"] for c in cards + existing},
        at=now(),
    )
    return store.update(task_id, {"source_result": result}, expected_revision=task["revision"])


def review_source_task(store, task_id, synthesis_task_id, verdict, note):
    task = store.get(task_id, "task")
    synth = store.get(synthesis_task_id, "task")
    if not result_current(store, task) or synth["role"] != "ir-synthesize" or synth["status"] != "running":
        raise ValueError(
            "Review a completed current source result from an independent running synthesis task"
        )
    if verdict not in ("supported", "needs_more_evidence"):
        raise ValueError("Use supported/needs_more_evidence")
    note = require_text(note, "note")
    with store.transaction() as con:
        current = store.get(task_id, "task", con)
        if (
            not result_current(store, current)
            or store.get(synthesis_task_id, "task", con)["status"] != "running"
        ):
            raise ValueError("Source result or reviewer changed during review")
        if current["revision"] != task["revision"]:
            raise ValueError("Source task changed; review again")
        store.update(
            task_id,
            {
                "source_review": dict(
                    synthesis_task_id=synthesis_task_id,
                    verdict=verdict,
                    note=note,
                    result_hash=digest(task["source_result"]),
                )
            },
            con=con,
        )
        lead = store.get(task["source_lead_id"], "source_lead", con)
        if verdict == "supported":
            store.update(
                lead["id"],
                {
                    "judgment": task["source_result"]["judgment"],
                    "judgment_note": note,
                    "judgment_task_id": task_id,
                    "revision_reason": "独立来源复核：" + note,
                },
                con=con,
                invalidate=True,
            )
        else:
            store.update(
                lead["id"], {"judgment_note": note, "judgment_task_id": task_id}, con=con, invalidate=True
            )
        return store.get(task_id, con=con)


def source_issues(store):
    issues = []
    tasks = list(store.all("task"))
    for lead in store.all("source_lead"):
        state = source_state(store, lead, tasks)
        if not state["complete"]:
            issues.append(
                dict(
                    code="SOURCE_REVIEW_PENDING",
                    object_id=lead["id"],
                    address=lead["address"],
                    state=state["state"],
                    missing_card_ids=state["missing_card_ids"],
                    task_ids=state["task_ids"],
                    action="Dispatch source review or independently review its current result",
                )
            )
    return issues


def source_task_issues(store, task, artifacts):
    if not task.get("source_lead_id"):
        return []
    r = task.get("source_result")
    issues = []
    if not r or not set(r["artifact_revisions"]).issubset(o["id"] for o in artifacts):
        return [
            dict(
                code="SOURCE_RESULT_MISSING",
                object_id=task["id"],
                action="complete_source_review and deliver its check/card IDs",
            )
        ]
    for oid, rev in r["artifact_revisions"].items():
        obj = store.get(oid)
        if (
            (
                obj["revision"] != rev
                and not (
                    obj["kind"] == "card"
                    and r.get("card_fingerprints", {}).get(oid) == card_entry(obj)["fingerprint"]
                )
            )
            or obj.get("status") in INVALID
            or pending(obj)
        ):
            issues.append(
                dict(
                    code="SOURCE_RESULT_CHANGED",
                    object_id=oid,
                    action="Recheck and complete_source_review again",
                )
            )
    return issues


def source_behavior_overview(store, lead_ids, dataset_ids, dimensions, time_field=None, max_rows=1000):
    """One grouped query for compatible sources. Never claims rows were individually inspected."""
    from .datasets import query_dataset

    if not 1 <= len(lead_ids) <= 30 or not dataset_ids or len(dimensions) > 6:
        raise ValueError("Select 1..30 sources, datasets and up to 6 behavior dimensions")
    leads = [store.get(lid, "source_lead") for lid in dict.fromkeys(lead_ids)]
    if len({(lead["field"], lead["match_mode"]) for lead in leads}) != 1:
        raise ValueError("Batch sources using the same field semantics; split incompatible schemas")
    field = leads[0]["field"]
    mode = leads[0]["match_mode"]
    columns = [field, *dimensions, *([time_field] if time_field else [])]
    if len(set(columns)) != len(columns):
        raise ValueError("Use distinct source, time and dimension fields")
    if any(
        not set(columns).issubset({c["name"] for c in store.get(did, "dataset")["schema"]})
        for did in dataset_ids
    ):
        raise ValueError(
            "Fields must exist in every selected dataset; inspect missing-schema partitions separately"
        )

    def ident(v):
        return '"' + v.replace('"', '""') + '"'

    def literal(v):
        return "'" + v.replace("'", "''") + "'"

    expression = f"TRIM(CAST({ident(field)} AS VARCHAR))"
    if mode == "forwarded_first":
        expression = f"TRIM(split_part(CAST({ident(field)} AS VARCHAR), ',', 1))"
    # Exact matches: never LIKE an IP prefix (e.g. .1 must not include .10).
    groups = ["_dataset_id", expression, *map(ident, dimensions)]
    sql = (
        "SELECT _dataset_id,"
        + expression
        + " AS source_address"
        + "".join("," + ident(d) for d in dimensions)
        + ",COUNT(*) AS record_count"
    )
    if time_field:
        sql += f",MIN(TRY_CAST({ident(time_field)} AS TIMESTAMPTZ)) AS first_observed,MAX(TRY_CAST({ident(time_field)} AS TIMESTAMPTZ)) AS last_observed,SUM(CASE WHEN {ident(time_field)} IS NOT NULL AND TRY_CAST({ident(time_field)} AS TIMESTAMPTZ) IS NULL THEN 1 ELSE 0 END) AS invalid_time_count"
    sql += (
        " FROM ir_all_events WHERE "
        + expression
        + " IN ("
        + ",".join(literal(lead["address"]) for lead in leads)
        + ") GROUP BY "
        + ",".join(groups)
        + " ORDER BY record_count DESC"
    )
    run = query_dataset(store, dataset_ids, sql, max_rows)
    return store.update(
        run["id"],
        {
            "source_overview": dict(
                lead_ids=lead_ids,
                dimensions=dimensions,
                time_field=time_field,
                note="All rows in selected partitions queried; grouped result may be truncated. Null times/unknown timezone require inspection. Exact textual IP spelling only; alternate IPv6 forms/ports require a normalized projection. Forwarded headers do not establish identity.",
            )
        },
    )
