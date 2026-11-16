"""Format-independent event cards and a derived investigation queue. No model scheduling."""

from datetime import datetime
from typing import Literal, NotRequired, TypedDict

from .integrity import parent_changed
from .store import dumps


class EventQuestion(TypedDict):
    question: str
    priority: NotRequired[Literal["critical", "optional"]]
    status: NotRequired[Literal["open", "bounded", "not_applicable"]]
    reason: NotRequired[str]
    check_ids: NotRequired[list[str]]


class EventSource(TypedDict):
    address: str
    field: str
    match_mode: Literal["exact", "forwarded_first"]
    attribution: NotRequired[Literal["direct_peer", "unverified", "trusted_proxy"]]
    check_ids: NotRequired[list[str]]


class EventTime(TypedDict):
    basis: Literal["recorded_offset", "inferred_offset", "unknown"]
    start: NotRequired[str]
    end: NotRequired[str]
    note: NotRequired[str]


class EventInput(TypedDict):
    title: str
    environment: str
    asset: str
    observed: str
    possible_causes: list[str]
    observed_effects: list[str]
    potential_impacts: list[str]
    upstream: EventQuestion
    downstream: EventQuestion
    claims: NotRequired[list[dict]]
    sources: NotRequired[list[EventSource]]
    timeline: NotRequired[EventTime]
    source_limitation: NotRequired[str]
    source_lead_ids: NotRequired[list[str]]


INVALID = {"stale", "rejected", "superseded"}

# Attack-path annotations. Not facts: excluded from fact_hash, so editing them never
# invalidates a card's follow-ups. Used only to order and group nodes in the timeline/path.
STAGES = (
    "recon",
    "initial_access",
    "credential",
    "execution",
    "persistence",
    "privilege",
    "lateral",
    "collection",
    "exfiltration",
    "impact",
    "unknown",
)
OUTCOMES = ("attempted", "blocked", "reached_app", "app_confirmed", "impact_confirmed", "unknown")
ANNOTATION_FIELDS = ("stage", "chains", "outcome", "key_time")


def text(value, name, limit=1500, empty=False):
    if not isinstance(value, str) or len(value) > limit or (not empty and not value.strip()):
        raise ValueError(
            f"{name}: expected {'optional' if empty else 'nonempty'} text, <= {limit} characters"
        )
    return value.strip()


def validate(store, event):
    required = {
        "title",
        "environment",
        "asset",
        "observed",
        "possible_causes",
        "observed_effects",
        "potential_impacts",
        "upstream",
        "downstream",
    }
    if (
        not isinstance(event, dict)
        or not required.issubset(event)
        or set(event) - required
        - {"claims", "source_lead_ids", "sources", "source_limitation", "timeline", *ANNOTATION_FIELDS}
    ):
        raise ValueError("event fields: " + ", ".join(sorted(required)))
    result = {
        k: text(event[k], k, 160 if k == "title" else 300 if k in {"environment", "asset"} else 1800)
        for k in ("title", "environment", "asset", "observed")
    }
    for key in ("possible_causes", "observed_effects", "potential_impacts"):
        if not isinstance(event[key], list) or len(event[key]) > 4:
            raise ValueError(f"{key}: use up to four concise statements; unknown may be []")
        result[key] = [text(s, key, 600) for s in event[key]]
    for direction in ("upstream", "downstream"):
        item = event[direction]
        if not isinstance(item, dict) or set(item) - {
            "question",
            "priority",
            "status",
            "reason",
            "check_ids",
        }:
            raise ValueError(f"{direction}: question, priority, status, reason, check_ids")
        status, priority = item.get("status", "open"), item.get("priority", "critical")
        if status not in ("open", "bounded", "not_applicable") or priority not in ("critical", "optional"):
            raise ValueError("Question status=open/bounded/not_applicable; priority=critical/optional")
        question = text(item.get("question", ""), direction + ".question", 800, status == "not_applicable")
        reason = text(
            item.get("reason", ""), direction + ".reason", 1200, status == "open" and priority == "critical"
        )
        ids = item.get("check_ids", [])
        if not isinstance(ids, list) or len(ids) > 10 or any(not isinstance(i, str) for i in ids):
            raise ValueError("check_ids: up to ten actual checks")
        if status == "bounded" and not ids:
            raise ValueError("A bounded question needs actual check_ids documenting the investigated limit")
        for cid in ids:
            if store.get(cid, "check")["status"] in INVALID:
                raise ValueError(f"Question references an outdated check: {cid}")
        result[direction] = dict(
            question=question, priority=priority, status=status, reason=reason, check_ids=ids
        )
    if event.get("claims"):
        from .integrity import validate_claims

        result["claims"] = validate_claims(
            store, [{k: v for k, v in c.items() if k != "statistic_snapshot"} for c in event["claims"]]
        )
        if any(c["scope"]["environment"] != result["environment"] for c in result["claims"]):
            raise ValueError("Claim environment must match event environment; split cross-environment events")
    if "sources" in event:
        from .source_leads import validate_sources

        result["sources"] = validate_sources(store, event["sources"])
    if event.get("source_limitation"):
        result["source_limitation"] = text(event["source_limitation"], "source_limitation", 1000)
    if "timeline" in event:
        result["timeline"] = validate_time(event["timeline"])
    ids = event.get("source_lead_ids", [])
    if not isinstance(ids, list) or len(ids) > 30 or any(not isinstance(i, str) for i in ids):
        raise ValueError("source_lead_ids: up to 30 registered sources")
    for lid in ids:
        store.get(lid, "source_lead")
    if ids:
        result["source_lead_ids"] = list(dict.fromkeys(ids))
    result.update(annotations(event))
    return result


def annotations(event):
    """Validate optional path annotations; absent fields stay absent."""
    out = {}
    if "stage" in event:
        if event["stage"] not in STAGES:
            raise ValueError("stage must be one of: " + ", ".join(STAGES))
        out["stage"] = event["stage"]
    if "outcome" in event:
        if event["outcome"] not in OUTCOMES:
            raise ValueError("outcome must be one of: " + ", ".join(OUTCOMES))
        out["outcome"] = event["outcome"]
    if "chains" in event:
        chains = event["chains"]
        if not isinstance(chains, list) or len(chains) > 6 or any(not isinstance(c, str) for c in chains):
            raise ValueError("chains: up to six short chain labels")
        cleaned = [text(c, "chain", 80) for c in chains]
        if len(set(cleaned)) != len(cleaned):
            raise ValueError("chains must be distinct")
        out["chains"] = cleaned
    if "key_time" in event:
        out["key_time"] = text(event["key_time"], "key_time", 45)
        timestamp(out["key_time"])  # must carry an explicit offset
    return out


def timestamp(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Event timestamps require an explicit UTC offset")
    return parsed


def validate_time(value):
    if not isinstance(value, dict) or set(value) - {"start", "end", "basis", "note"}:
        raise ValueError("timeline: start, end, basis and note")
    basis = value.get("basis")
    if basis not in {"recorded_offset", "inferred_offset", "unknown"}:
        raise ValueError("timeline.basis: recorded_offset, inferred_offset, or unknown")
    note = text(value.get("note", ""), "timeline.note", 600, empty=basis == "recorded_offset")
    if basis == "unknown":
        if value.get("start") or value.get("end"):
            raise ValueError("Leave structured timestamps empty when the offset/time is unknown")
        return dict(basis=basis, note=note)
    start = text(value.get("start", ""), "timeline.start", 45)
    end = text(value.get("end", start), "timeline.end", 45)
    if timestamp(end) < timestamp(start):
        raise ValueError("timeline.end precedes start")
    return dict(start=start, end=end, basis=basis, note=note)


def dependencies(event):
    # Question checks are workflow references, not premises of the observed event.
    # Their currency is checked by direction_state; adding causal edges creates parent/check cycles.
    return []


def direction_state(store, card, direction, tasks=None):
    q = card["event"][direction]
    state = {**q, "direction": direction, "card_id": card["id"], "task_ids": [], "blocking": False}
    if q["status"] != "open":
        checks = [store.get(cid, "check") for cid in q.get("check_ids", [])]
        state["state"] = q["status"] if all(c["status"] not in INVALID for c in checks) else "stale"
    else:
        linked = [
            t
            for t in (tasks if tasks is not None else store.all("task"))
            if t.get("parent_card_id") == card["id"]
            and not parent_changed(t, card)
            and t.get("direction") in (direction, "both")
        ]
        state["task_ids"] = [t["id"] for t in linked]
        state["state"] = "open"
        if linked:
            task_states = []
            for task in linked:
                if task["status"] != "completed":
                    task_states.append("assigned")
                    continue
                review = task.get("followup_review") or {}
                artifacts = [store.get(oid) for oid in task.get("artifact_ids", [])]
                from .board import current_followup_review

                if (
                    current_followup_review(task, review.get("synthesis_task_id"), artifacts)
                    and review.get("verdict") == "supported"
                ):
                    task_states.append("reviewed")
                else:
                    task_states.append(
                        "needs_evidence"
                        if review.get("verdict") == "needs_more_evidence"
                        else "awaiting_review"
                    )
            state["state"] = next(
                name
                for name in ("needs_evidence", "assigned", "awaiting_review", "reviewed")
                if name in task_states
            )
    state["blocking"] = q["priority"] == "critical" and state["state"] not in (
        "bounded",
        "not_applicable",
        "reviewed",
    )
    return state


def event_queue(store, limit=30, offset=0):
    if not 1 <= limit <= 100 or offset < 0:
        raise ValueError("Use limit 1..100 and offset >=0")
    tasks = list(store.all("task"))
    rows = []
    for card in store.all("card"):
        from .integrity import pending

        if pending(card) and card["status"] not in ("rejected", "superseded"):
            rows.append(
                dict(
                    card_id=card["id"],
                    direction="review",
                    state="needs_review",
                    question="Revalidate distinct facts and evidence after premise changes",
                    task_ids=[],
                    blocking=True,
                    title=card.get("event", {}).get("title", card["statement"]),
                    revision=card["revision"],
                )
            )
        if not card.get("event") or card["status"] in INVALID:
            continue
        for side in ("upstream", "downstream"):
            item = direction_state(store, card, side, tasks)
            if item["blocking"]:
                item.update(title=card["event"]["title"], revision=card["revision"])
                rows.append(item)
    return {
        "questions": rows[offset : offset + limit],
        "total": len(rows),
        "next_offset": offset + limit if offset + limit < len(rows) else None,
    }


def submit_event(
    store, event, evidence, time_range, task_id, entities=None, depends_on=None, submission_key=None
):
    from .board import submit_card

    event = validate(store, event)
    # Prevent exact duplicate event nodes without pretending semantic similarity is identity.
    for card in store.all("card"):
        previous = card.get("event", {})
        if (
            card["status"] not in INVALID
            and card.get("time_range") == time_range
            and all(previous.get(k) == event[k] for k in ("title", "environment", "asset"))
        ):
            if submission_key and card.get("event") == event:
                break  # Store's idempotency key still validates all evidence and inputs.
            raise ValueError(
                f"Existing event {card['id']} r{card['revision']}; inspect it and use revise_event if this is the same event"
            )
    return submit_card(
        store,
        event["title"] + "\n" + event["observed"],
        "observation",
        evidence,
        entities,
        time_range,
        depends_on,
        submission_key,
        task_id,
        event=event,
    )


def revise_event(
    store, card_id, expected_revision, event, evidence, reason, remove_evidence=None, remove_claims=None
):
    from .board import revise_card

    old = store.get(card_id, "card")
    # Omission preserves associations; an explicit [] withdraws them with the revision reason.
    event = {
        **event,
        "source_lead_ids": event.get("source_lead_ids", old.get("event", {}).get("source_lead_ids", [])),
    }
    for field in ("sources", "source_limitation", "timeline", *ANNOTATION_FIELDS):
        if field not in event and field in old.get("event", {}):
            event[field] = old["event"][field]
    removed = remove_claims or {}
    prior = {c["key"]: c for c in old.get("event", {}).get("claims", [])}
    if any(k not in prior or not isinstance(v, str) or not v.strip() for k, v in removed.items()):
        raise ValueError("remove_claims maps existing claim keys to explicit withdrawal reasons")
    proposed = {c["key"]: c for c in event.get("claims", [])}
    if set(removed) & set(proposed):
        raise ValueError("Cannot withdraw a claim and submit it in the same revision")
    merged = {**{k: v for k, v in prior.items() if k not in removed}, **proposed}
    if prior and not merged:
        raise ValueError("Use resolve_review(withdraw/merge) to retire an event with no remaining claims")
    event = validate(store, {**event, **({"claims": list(merged.values())} if merged else {})})
    return revise_card(
        store,
        card_id,
        expected_revision,
        event["title"] + "\n" + event["observed"],
        evidence,
        reason,
        event=event,
        remove_evidence=remove_evidence,
        removed_claims={k: {"claim": prior[k], "reason": v} for k, v in removed.items()},
    )


def report_lines(card):
    e = card["event"]
    lines = [
        f"事件：{e['title']}",
        f"环境/资产：{e['environment']} / {e['asset']}",
        f"已观察行为：{e['observed']}",
        "可能前因（假设）：" + "；".join(e["possible_causes"] or ["未知"]),
        "已观察后果：" + "；".join(e["observed_effects"] or ["暂无结果证据"]),
        "潜在影响（假设）：" + "；".join(e["potential_impacts"] or ["待判断"]),
    ]
    for side, label in (("upstream", "前因"), ("downstream", "后果")):
        lines.append(f"{label}问题：{dumps(e[side])}")
    return lines


def annotate_path(store, card_id, expected_revision, stage=None, chains=None, outcome=None, key_time=None):
    """Set attack-path annotations on an event card without altering its observed facts.

    Excluded from fact_hash, so this never invalidates the card's follow-ups or checks.
    Only cards that already carry a structured event can be annotated.
    """
    card = store.get(card_id, "card")
    if not card.get("event"):
        raise ValueError("Only structured event cards carry path annotations")
    if card["status"] in INVALID:
        raise ValueError("Resolve the card's review/disposition before annotating its path")
    requested = {"stage": stage, "chains": chains, "outcome": outcome, "key_time": key_time}
    provided = {k: v for k, v in requested.items() if v is not None}
    if not provided:
        raise ValueError("Provide at least one of stage, chains, outcome, key_time")
    merged = {**{k: card["event"][k] for k in ANNOTATION_FIELDS if k in card["event"]}, **provided}
    checked = annotations({**card["event"], **merged})
    event = {**card["event"], **checked}
    return store.update(card_id, {"event": event}, expected_revision=expected_revision)
