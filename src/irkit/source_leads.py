"""Read-only projection of event sources and ordinary checks, including legacy records.

No source objects, snapshots, tasks or workflow states are created here.
"""

import hashlib
import ipaddress
import json

from .integrity import pending

INVALID = {"stale", "rejected", "superseded"}


def validate_sources(store, entries):
    if not isinstance(entries, list) or len(entries) > 100:
        raise ValueError("sources: up to 100 explicit source entries")
    result, seen = [], set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) - {
            "address",
            "field",
            "match_mode",
            "attribution",
            "check_ids",
        }:
            raise ValueError("source: address, field, match_mode, attribution, check_ids")
        address = str(ipaddress.ip_address(entry.get("address", "")))
        field = entry.get("field")
        if not isinstance(field, str) or not field.strip() or len(field) > 300:
            raise ValueError("source.field: actual nonempty log field required")
        mode, trust = entry.get("match_mode"), entry.get("attribution", "unverified")
        if mode not in ("exact", "forwarded_first") or trust not in (
            "direct_peer",
            "unverified",
            "trusted_proxy",
        ):
            raise ValueError("source match_mode/attribution invalid")
        ids = entry.get("check_ids", [])
        if not isinstance(ids, list) or len(ids) > 100 or any(not isinstance(i, str) for i in ids):
            raise ValueError("source.check_ids: up to 100 actual check IDs")
        for cid in ids:
            store.get(cid, "check")
        key = (address, field.strip(), mode, trust)
        if key in seen:
            raise ValueError("Duplicate source in event; combine check_ids")
        seen.add(key)
        result.append(
            dict(
                address=address,
                field=field.strip(),
                match_mode=mode,
                attribution=trust,
                check_ids=list(dict.fromkeys(ids)),
            )
        )
    return result


def card_sources(store, card, leads=None):
    event = card.get("event", {})
    # Explicit [] also withdraws legacy associations. Never guess from entities/asset IPs.
    if "sources" in event:
        return event["sources"]
    leads = leads if leads is not None else {x["id"]: x for x in store.all("source_lead")}
    result = []
    for lid in event.get("source_lead_ids", []):
        lead = leads.get(lid)
        if lead:
            result.append(
                {
                    **{
                        k: lead.get(k, "unverified")
                        for k in ("address", "field", "match_mode", "attribution")
                    },
                    "check_ids": [],
                    "legacy_id": lid,
                }
            )
    return result


def source_overview(store, limit=30, offset=0):
    if not 1 <= limit <= 100 or offset < 0:
        raise ValueError("Use limit 1..100 and offset >=0")
    rows = aggregate(store)
    return {
        "sources": rows[offset : offset + limit],
        "total": len(rows),
        "next_offset": offset + limit if offset + limit < len(rows) else None,
    }


def aggregate(store):
    leads = {x["id"]: x for x in store.all("source_lead")}
    checks = {x["id"]: x for x in store.all("check")}
    tasks = list(store.all("task"))
    legacy_tasks = [t for t in tasks if t.get("source_lead_id")]
    grouped = {}
    for card in store.all("card"):
        event = card.get("event", {})
        for source in card_sources(store, card, leads):
            key = [source[k] for k in ("address", "field", "match_mode", "attribution")]
            oid = "source_view_" + hashlib.sha256(json.dumps(key).encode()).hexdigest()[:16]
            row = grouped.setdefault(
                oid,
                dict(
                    id=oid,
                    kind="source_view",
                    **dict(zip(("address", "field", "match_mode", "attribution"), key)),
                    cards=[],
                    checks=[],
                    gaps=[],
                    legacy_task_ids=[],
                ),
            )
            current = card["status"] not in INVALID and not pending(card)
            row["cards"].append(
                dict(
                    id=card["id"],
                    revision=card["revision"],
                    status=card["status"],
                    current=current,
                    title=event.get("title", card.get("statement", "")),
                    environment=event.get("environment", "unknown"),
                    asset=event.get("asset", "unknown"),
                    time_range=card.get("time_range", "unknown"),
                )
            )
            ids = list(source.get("check_ids", []))
            legacy_ids = []
            legacy_conclusions = {}
            for task in legacy_tasks if source.get("legacy_id") else []:
                if task["source_lead_id"] != source["legacy_id"]:
                    continue
                row["legacy_task_ids"].append(task["id"])
                covered = set(task.get("source_snapshot", {}).get("cards", {})) | set(
                    task.get("source_result", {}).get("finding_card_ids", [])
                )
                if card["id"] not in covered:
                    continue
                legacy_ids += [oid for oid in task.get("artifact_ids", []) if oid in checks]
                for category in task.get("source_result", {}).get("behavior_categories", []):
                    legacy_ids += category.get("check_ids", [])
                    for cid in category.get("check_ids", []):
                        legacy_conclusions.setdefault(cid, []).append(
                            category.get("behavior", "") + ": " + category.get("conclusion", "")
                        )
            valid = False
            for cid in dict.fromkeys(ids + legacy_ids):
                check = checks.get(cid)
                if not check:
                    row["gaps"].append(f"{card['id']}: check {cid} unavailable")
                    continue
                legacy = cid not in ids
                usable = current and check["status"] not in INVALID and not pending(check) and not legacy
                valid |= usable
                row["checks"].append(
                    {
                        **{
                            k: check.get(k)
                            for k in (
                                "id",
                                "revision",
                                "status",
                                "question",
                                "scope",
                                "outcome",
                                "conclusion",
                                "limitations",
                                "query_ids",
                                "source_operation_profiles",
                                "task_id",
                            )
                        },
                        "conclusion": check.get("conclusion")
                        or "; ".join(dict.fromkeys(legacy_conclusions.get(cid, []))),
                        "card_id": card["id"],
                        "current": usable,
                        "historical": legacy,
                    }
                )
            if not valid:
                row["gaps"].append(f"{card['id']}: 尚无当前有效的来源行为检查；不代表没有攻击")
            for direction in ("upstream", "downstream"):
                q = event.get(direction, {})
                from .events import direction_state

                if q and direction_state(store, card, direction, tasks)["state"] not in (
                    "bounded",
                    "not_applicable",
                    "reviewed",
                ):
                    row["gaps"].append(
                        f"{card['id']} {direction}: {q.get('question', '')}（处理情况见事件补证）"
                    )
    for row in grouped.values():
        row["legacy_task_ids"] = sorted(set(row["legacy_task_ids"]))
        row["gaps"] = list(dict.fromkeys(row["gaps"]))
    return sorted(
        grouped.values(), key=lambda x: (x["address"], x["field"], x["match_mode"], x["attribution"])
    )
