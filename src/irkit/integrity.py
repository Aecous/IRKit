"""Evidence-preserving revisions and bounded claim contracts; no scheduler or model calls."""

import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import datetime

from .store import dumps, now

INVALID = {"stale", "rejected", "superseded"}


def pending(obj):
    return obj.get("review_state") == "needs_review" or obj.get("status") == "stale"


def disposed(obj):
    return obj.get("status") in ("rejected", "superseded") and obj.get("disposition", {}).get("decision") in (
        "merge",
        "withdraw",
    )


def fact_hash(card):
    event = {
        k: v
        for k, v in card.get("event", {}).items()
        if k not in ("upstream", "downstream", "source_lead_ids", "sources")
    }
    if "sources" in card.get("event", {}):
        event["sources"] = [
            {k: v for k, v in source.items() if k != "check_ids"} for source in card["event"]["sources"]
        ]
    content = [card.get("statement"), card.get("evidence"), card.get("time_range"), event]
    return hashlib.sha256(json.dumps(content, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def parent_changed(task, parent):
    return (
        parent["status"] in INVALID
        or pending(parent)
        or (
            task["parent_fact_hash"] != fact_hash(parent)
            if task.get("parent_fact_hash")
            else task["parent_card_revision"] != parent["revision"]
        )
    )


def unique_refs(refs):
    return list({json.dumps(r, sort_keys=True): r for r in refs}.values())


def history(store, object_id, offset=0, limit=20):
    store.get(object_id)
    if not 1 <= limit <= 50 or offset < 0:
        raise ValueError("Use limit 1..50 and offset >=0")
    with closing(sqlite3.connect(store.db)) as con:
        total = con.execute("SELECT count(*) FROM changes WHERE object_id=?", (object_id,)).fetchone()[0]
        rows = con.execute(
            "SELECT seq,at,action,detail FROM changes WHERE object_id=? ORDER BY seq DESC LIMIT ? OFFSET ?",
            (object_id, limit, offset),
        ).fetchall()
    results = []
    for seq, at, action, raw in rows:
        d = json.loads(raw)
        patch, before = d.get("patch", d), d.get("before", {})
        old, new = before.get("evidence", []), patch.get("evidence", before.get("evidence", []))
        results.append(
            dict(
                seq=seq,
                at=at,
                action=action,
                revision=before.get("revision", 0) + 1,
                reason=patch.get("revision_reason") or patch.get("disposition", {}).get("reason"),
                changed_fields=list(patch),
                evidence_added=[r for r in new if r not in old],
                evidence_removed=[r for r in old if r not in new],
                review_state=patch.get("review_state"),
                review_causes=patch.get("review_causes"),
                disposition=patch.get("disposition"),
            )
        )
    return dict(
        items=results, total=total, next_offset=offset + len(rows) if offset + len(rows) < total else None
    )


def resolve_review(store, object_id, expected_revision, decision, reason, synthesis_task_id, target_ids=None):
    """Retain, merge or withdraw, recording an explicit disposition rather than hiding facts."""
    from .board import validate_refs

    if decision not in ("retain", "merge", "withdraw") or not reason.strip():
        raise ValueError("Choose retain/merge/withdraw and explain the evidence assessment")
    with store.transaction() as con:
        obj = store.get(object_id, con=con)
        if obj["revision"] != expected_revision:
            raise ValueError(
                f"Revision conflict for {object_id}: expected {expected_revision}, actual {obj['revision']}; get_object then review_plan before retrying"
            )
        if obj["kind"] not in ("card", "link", "check"):
            raise ValueError("Only cards, links and checks can be revalidated")
        if obj["status"] in ("rejected", "superseded"):
            raise ValueError("Already disposed; create a corrected event instead")
        synth = store.get(synthesis_task_id, "task", con)
        if synth["role"] != "ir-synthesize" or synth["status"] != "running":
            raise ValueError("A running synthesis task must review the disposition")
        targets = [store.get(i, obj["kind"], con) for i in target_ids or []]
        if decision == "merge":
            if not targets or any(
                t["id"] == object_id or pending(t) or t["status"] in INVALID for t in targets
            ):
                raise ValueError("Merge requires current distinct target objects")
            for target in targets:
                ancestors = con.execute(
                    "WITH RECURSIVE ancestors(id) AS (SELECT parent FROM dependencies WHERE child=? "
                    "UNION SELECT d.parent FROM dependencies d JOIN ancestors a ON d.child=a.id) "
                    "SELECT id FROM ancestors",
                    (target["id"],),
                ).fetchall()
                if any(row[0] == object_id for row in ancestors):
                    raise ValueError("Merge target must not depend on the object being retired")
            if obj["kind"] == "card":
                migrated = unique_refs([r for t in targets for r in t.get("evidence", [])])
                if any(r not in migrated for r in obj["evidence"]):
                    raise ValueError("Migrate original evidence to target cards before merging")
                claims = [c for t in targets for c in t.get("event", {}).get("claims", [])]
                for claim in obj.get("event", {}).get("claims", []):
                    if not any(
                        all(c.get(k) == claim.get(k) for k in ("statement", "evidence", "scope", "level"))
                        for c in claims
                    ):
                        raise ValueError("Migrate each distinct claim to a target before merging")
        elif targets:
            raise ValueError("target_ids are only used for merge")
        if decision == "retain":
            # Unchanged facts still require fresh checks of their current premises.
            store.assert_live_dependencies(object_id, con)
            if obj.get("evidence"):
                validate_refs(store, obj["evidence"])
            if obj["kind"] == "check":
                for snap in obj.get("body_evidence", []):
                    run = store.get(snap["id"], "run", con)
                    if run["revision"] != snap["revision"] or run["status"] != "succeeded":
                        raise ValueError("Body evidence changed; submit a new check")
                for qid in obj["query_ids"]:
                    run = store.get(qid, "run", con)
                    if run["status"] != "succeeded" or run.get("truncated"):
                        raise ValueError("Recheck failed or truncated queries")
                    for did in run["datasets"]:
                        if store.get(did, "dataset", con)["status"] in INVALID:
                            raise ValueError("Recheck superseded datasets")
            for (dep,) in con.execute("SELECT parent FROM dependencies WHERE child=?", (object_id,)):
                if pending(store.get(dep, con=con)):
                    raise ValueError("Review the changed premise first: " + dep)
        disposition = dict(
            decision=decision,
            reason=reason,
            target_ids=target_ids or [],
            synthesis_task_id=synthesis_task_id,
            at=now(),
            from_revision=obj["revision"],
        )
        return store.update(
            object_id,
            dict(
                status="candidate"
                if decision == "retain"
                else "superseded"
                if decision == "merge"
                else "rejected",
                review_state="current",
                review_causes={},
                disposition=disposition,
                disposition_history=[*obj.get("disposition_history", []), disposition],
            ),
            expected_revision=expected_revision,
            invalidate=decision != "retain",
            con=con,
        )


def environment_names(store):
    names = {}
    for obj in store.all("environment_alias"):
        names.update({label: obj["canonical"] for label in obj["labels"]})
    return names


def register_environment_alias(store, canonical, labels, card_ids, reason, synthesis_task_id):
    """Explicit reviewed aliases, never infer equality from addresses or fuzzy text."""
    if (
        not isinstance(labels, list)
        or not 2 <= len(set(labels)) <= 20
        or canonical not in labels
        or not reason.strip()
    ):
        raise ValueError("Choose an existing canonical label, 2..20 exact aliases and explain the evidence")
    with store.transaction() as con:
        synth = store.get(synthesis_task_id, "task", con)
        if synth["role"] != "ir-synthesize" or synth["status"] != "running":
            raise ValueError("A running independent synthesis task must assess environment aliases")
        cards = [store.get(cid, "card", con) for cid in card_ids]
        observed = {c.get("event", {}).get("environment") for c in cards}
        if not set(labels).issubset(observed):
            raise ValueError("Each alias needs a referenced event using that label")
        prior = environment_names(store)
        if any(label in prior and prior[label] != canonical for label in labels):
            raise ValueError("Alias conflicts with an existing mapping; do not silently merge environments")
        for existing in store.all("environment_alias"):
            if existing["canonical"] == canonical and set(existing["labels"]) == set(labels):
                return existing
        obj = store.put(
            "environment_alias",
            dict(
                canonical=canonical,
                labels=sorted(set(labels)),
                card_ids=card_ids,
                reason=reason,
                synthesis_task_id=synthesis_task_id,
                status="current",
            ),
            con=con,
        )
        for report in store.all("report"):
            store.update(report["id"], {"status": "stale", "stale_because": obj["id"]}, con=con)
        return obj


def review_plan(store, limit=50):
    """Return current revisions and dependency order without changing evidence."""
    if not 1 <= limit <= 100:
        raise ValueError("Use limit 1..100")
    candidates = {
        o["id"]: o
        for kind in ("card", "check", "link")
        for o in store.all(kind)
        if pending(o) and not disposed(o)
    }
    with closing(sqlite3.connect(store.db)) as con:
        parents = {
            oid: [r[0] for r in con.execute("SELECT parent FROM dependencies WHERE child=?", (oid,))]
            for oid in candidates
        }
    ready = []
    blocked = []
    for oid, obj in candidates.items():
        dependencies = [store.get(i) for i in parents[oid]]
        blockers = [
            {
                "id": o["id"],
                "revision": o["revision"],
                "status": o["status"],
                "review_state": o.get("review_state"),
            }
            for o in dependencies
            if pending(o) or o["status"] in INVALID
        ]
        item = dict(id=oid, kind=obj["kind"], revision=obj["revision"], blocked_by=blockers)
        (blocked if blockers else ready).append(item)
    return dict(
        ready=ready[:limit],
        blocked=blocked[:limit],
        ready_count=len(ready),
        blocked_count=len(blocked),
        action="Review ready parents first; read this plan again after each dependent mutation. Never reuse cached revisions across a dependency chain.",
    )


def stamp(value):
    if not isinstance(value, str):
        raise ValueError("Time bounds must be ISO timestamps with timezone")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Time bounds need an explicit timezone")
    return parsed


def evidence_rows(store, refs):
    from .datasets import dataset_row
    from .evidence import source_records

    rows = []
    for ref in refs:
        if "dataset_id" in ref:
            rows.append(dataset_row(store, ref["dataset_id"], ref["row_id"]))
        elif "source_id" in ref:
            if ref["end"] - ref["start"] > 20:
                raise ValueError("Claim anchors must use <=21 original lines per reference")
            with closing(
                source_records(store, ref["source_id"], ref.get("encoding", "latin-1"), ref["start"])
            ) as stream:
                for line, raw in stream:
                    if line > ref["end"]:
                        break
                    try:
                        row = json.loads(raw)
                    except ValueError:
                        continue  # Text/EVTX claims can use a structured dataset row.
                    if isinstance(row, dict):
                        rows.append(row)
    return rows


def check_scope(scope, rows, strict=False):
    """Compare explicit dimensions, never infer an environment name from private IP ranges."""
    for key, values in scope.get("dimensions", {}).items():
        if not isinstance(values, list) or not values or not all(isinstance(v, (str, int)) for v in values):
            raise ValueError("Scope dimensions use nonempty arrays of exact field values")
        present = [r[key] for r in rows if key in r]
        if (strict and len(present) != len(rows)) or not present:
            raise ValueError(f"Scope dimension {key} not projected in evidence; include it in the query/row")
        if any(v not in values for v in present):
            raise ValueError(f"Scope mismatch for {key}: evidence is outside declared values")
    if scope.get("time_from") or scope.get("time_to"):
        low, high = stamp(scope["time_from"]), stamp(scope["time_to"])
        if high < low:
            raise ValueError("Reversed time scope")
        field = scope.get("time_field")
        if not field:
            raise ValueError("Specify time_field for a bounded claim")
        values = [r[field] for r in rows if r.get(field)]
        if not values:
            raise ValueError("Time field missing from evidence")
        for value in values:
            if not low <= stamp(str(value)) <= high:
                raise ValueError("Evidence time is outside the declared scope")


def validate_claims(store, claims):
    from .board import validate_refs
    from .datasets import read_query_result

    if not isinstance(claims, list) or not 1 <= len(claims) <= 12:
        raise ValueError("Use 1..12 atomic claims per event")
    result, keys = [], set()
    for item in claims:
        if not isinstance(item, dict) or set(item) - {
            "key",
            "statement",
            "level",
            "evidence",
            "scope",
            "statistic",
        }:
            raise ValueError("Claim fields: key, statement, level, evidence, scope, statistic")
        if any(not isinstance(item.get(k), str) or not item[k].strip() for k in ("key", "statement")):
            raise ValueError("Claim key and statement required")
        if len(item["key"]) > 80 or len(item["statement"]) > 1000 or item["key"] in keys:
            raise ValueError("Use short unique claim keys and concise statements")
        keys.add(item["key"])
        if item.get("level") not in ("request", "response", "application", "inference"):
            raise ValueError("Claim level=request/response/application/inference")
        validate_refs(store, item.get("evidence"))
        scope = item.get("scope", {})
        if not isinstance(scope, dict) or set(scope) - {
            "environment",
            "dimensions",
            "time_field",
            "time_from",
            "time_to",
        }:
            raise ValueError("Scope: environment, dimensions, time_field, time_from, time_to")
        if not isinstance(scope.get("environment"), str) or not scope["environment"].strip():
            raise ValueError("Explicit environment required; use unknown when not established")
        if not isinstance(scope.get("dimensions", {}), dict):
            raise ValueError("dimensions must be a field-to-values mapping")
        claim = dict(item)
        statistic = item.get("statistic")
        if statistic:
            if set(statistic) != {"query_id", "row", "column", "unit", "population"}:
                raise ValueError(
                    "Statistic selects query_id/row/column/unit/population; value is tool-derived"
                )
            if not all(
                isinstance(statistic[k], str) and statistic[k].strip()
                for k in ("unit", "population", "column")
            ):
                raise ValueError("Statistic needs a unit and exact population description")
            if type(statistic["row"]) is not int or statistic["row"] < 0:
                raise ValueError("Statistic row is a zero-based integer")
            run = store.get(statistic["query_id"], "run")
            if {"query_id": run["id"]} not in item["evidence"]:
                raise ValueError("Statistic query must be in claim evidence")
            rows = read_query_result(store, run["id"], statistic["row"], 1)["rows"]
            if not rows or statistic["column"] not in rows[0]:
                raise ValueError("Statistic result cell does not exist")
            row = rows[0]
            check_scope(scope, rows, strict=True)
            claim["statistic_snapshot"] = dict(
                **statistic,
                value=row[statistic["column"]],
                result_row=row,
                sql=run["sql"],
                datasets=run["datasets"],
                truncated=run.get("truncated", False),
                query_revision=run["revision"],
                selection_note="Value covers this SQL and result group only; LIMIT may restrict scope",
            )
        else:
            if not any("source_id" in r or "dataset_id" in r for r in item["evidence"]):
                raise ValueError(
                    "Event claims require original lines or dataset rows; aggregates are not event evidence"
                )
            check_scope(scope, evidence_rows(store, item["evidence"]))
        result.append(claim)
    return result


def delivery_issues(store):
    issues = []
    for kind in ("card", "link"):
        for obj in store.all(kind):
            if pending(obj) and obj["status"] not in ("rejected", "superseded"):
                issues.append(
                    dict(
                        code="EVIDENCE_REVIEW_PENDING",
                        object_id=obj["id"],
                        kind=kind,
                        stale_because=obj.get("stale_because"),
                        action="Retain after review, migrate facts before merge, or withdraw with reason",
                    )
                )
            if (
                obj.get("status") in ("rejected", "superseded")
                and not disposed(obj)
                and (obj.get("review") or {}).get("actor") != "human_cli"
            ):
                issues.append(
                    dict(
                        code="DISPOSITION_MISSING",
                        object_id=obj["id"],
                        action="Record an explicit disposition",
                    )
                )
    # Claims sharing an exact asset identifier cannot silently change environment labels.
    assignments = {}
    names = environment_names(store)
    for card in store.all("card"):
        if card["status"] in INVALID:
            continue
        for claim in card.get("event", {}).get("claims", []):
            scope = claim["scope"]
            for field in ("host", "domain", "Computer", "asset_id"):
                for value in scope.get("dimensions", {}).get(field, []):
                    assignments.setdefault((field, str(value)), {}).setdefault(
                        names.get(scope["environment"], scope["environment"]), []
                    ).append(card["id"])
    for (field, value), environments in assignments.items():
        if len(environments) > 1:
            issues.append(
                dict(
                    code="ENVIRONMENT_CONFLICT",
                    field=field,
                    value=value,
                    assignments=environments,
                    action="Reconcile asset/environment mapping; shared gateways need an explicit shared environment",
                )
            )
    return issues


def delivery_snapshot(store):
    kinds = ("card", "link", "check", "environment_alias")
    if any(t.get("event_policy_version", 0) >= 4 for t in store.all("task")):
        kinds += ("source", "dataset", "input_gap")
    return {o["id"]: o["revision"] for kind in kinds for o in store.all(kind)}


def review_delivery(store, synthesis_task_id, decisions, note):
    """Explicit per-card coverage, including historical findings; snapshots prevent post-review drift."""
    synth = store.get(synthesis_task_id, "task")
    if synth["role"] != "ir-synthesize" or synth["status"] != "running" or not note.strip():
        raise ValueError("Use running synthesis and explain environment/statistics/causal review")
    items = {o["id"]: o for kind in ("card", "link") for o in store.all(kind)}
    if set(decisions) != set(items):
        raise ValueError("Provide one review note for every card and link, including disposed ones")
    if any(not isinstance(v, str) or not v.strip() for v in decisions.values()):
        raise ValueError("Each review note must address evidence, distinct facts and relationship support")
    issues = delivery_issues(store)
    if issues:
        raise ValueError(dumps(issues))
    return store.put(
        "run",
        dict(
            operation="delivery_review",
            status="succeeded",
            synthesis_task_id=synthesis_task_id,
            decisions=decisions,
            note=note,
            snapshot=delivery_snapshot(store),
            at=now(),
        ),
    )


def trace_events(
    store, dataset_ids, entity_filters, time_field, time_from, time_to, columns, state_field, max_rows=500
):
    """A bounded chronology preserving all outcomes, not a product-specific correlation engine."""
    from .datasets import query_dataset

    if not entity_filters or not isinstance(entity_filters, dict) or not 1 <= max_rows <= 2000:
        raise ValueError("Explicit entity filters and max_rows 1..2000 required")
    if stamp(time_to) < stamp(time_from):
        raise ValueError("Reversed time window")
    schemas = [{c["name"] for c in store.get(d, "dataset")["schema"]} for d in dataset_ids]
    if not schemas:
        raise ValueError("Select datasets")
    available = set.union(*schemas)
    selected = list(dict.fromkeys([time_field, *entity_filters, state_field, *columns]))
    if not all(isinstance(c, str) and c in available for c in selected):
        raise ValueError("Choose real schema columns for time, entity, state and projection")
    if len(selected) > 24 or any(len(v) == 0 or len(v) > 20 for v in entity_filters.values()):
        raise ValueError("At most 24 columns and 1..20 values per entity filter")

    def ident(s):
        return '"' + s.replace('"', '""') + '"'

    def literal(s):
        if not isinstance(s, str):
            raise ValueError("Use exact string values for entity filters")
        return "'" + s.replace("'", "''") + "'"

    where = [
        f"{ident(k)} IN ({','.join(literal(v) for v in values)})" for k, values in entity_filters.items()
    ]
    where += [
        f"TRY_CAST({ident(time_field)} AS TIMESTAMPTZ) BETWEEN "
        f"{literal(time_from)}::TIMESTAMPTZ AND {literal(time_to)}::TIMESTAMPTZ"
    ]
    sql = (
        "SELECT _dataset_id,_row_id,_refs,"
        + ",".join(ident(c) for c in selected)
        + " FROM ir_all_events WHERE "
        + " AND ".join(where)
        + f" ORDER BY TRY_CAST({ident(time_field)} AS TIMESTAMPTZ),_dataset_id,_row_id"
    )
    run = query_dataset(store, dataset_ids, sql, max_rows)
    return store.update(
        run["id"],
        {
            "trace_scope": dict(
                entity_filters=entity_filters,
                time_field=time_field,
                time_from=time_from,
                time_to=time_to,
                state_field=state_field,
                note="All states retained. Read all result pages; on truncation narrow the window. "
                "Compare before/change/retry per entity; temporal adjacency is not causation.",
            )
        },
    )
