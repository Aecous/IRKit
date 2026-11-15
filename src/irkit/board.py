from __future__ import annotations

from .datasets import dataset_row
from .evidence import case_metadata, raw_ref
from .integrity import disposed, fact_hash, parent_changed, pending, unique_refs
from .store import dumps, now


def validate_refs(store, refs):
    if not isinstance(refs, list) or not refs or len(refs) > 100:
        raise ValueError("Supply 1..100 evidence refs")
    dependencies = []
    for ref in refs:
        if "source_id" in ref:
            dependencies.append(raw_ref(store, ref))
        elif set(ref) == {"dataset_id", "row_id"}:
            dataset_row(store, ref["dataset_id"], ref["row_id"])
            ds = store.get(ref["dataset_id"], "dataset")
            if ds["status"] == "superseded":
                raise ValueError("Use the replacement dataset")
            dependencies.append(ref["dataset_id"])
        elif set(ref) == {"query_id"}:
            run = store.get(ref["query_id"], "run")
            if run.get("operation") != "query" or run["status"] != "succeeded":
                raise ValueError("Evidence must reference a successful query")
            for did in run["datasets"]:
                if store.get(did, "dataset")["status"] == "superseded":
                    raise ValueError("Query used superseded data; rerun")
            dependencies.append(ref["query_id"])
        else:
            raise ValueError("Expected raw range, dataset row, or query_id reference")
    return dependencies


def submit_card(
    store,
    statement,
    card_type,
    evidence,
    entities=None,
    time_range=None,
    depends_on=None,
    submission_key=None,
    task_id=None,
    event=None,
):
    if card_type not in ("observation", "inference") or not statement.strip() or len(statement) > 6000:
        raise ValueError("Use observation/inference and a statement of 1..6000 chars")
    if task_id:
        task = store.get(task_id, "task")
        if not (event and task["role"] == "ir-synthesize" and task["status"] == "running"):
            task = active_investigation(store, task_id)
        if task.get("event_policy_version") and event is None:
            raise ValueError(
                "Use submit_event with structured behavior, causes, effects and investigation questions"
            )
        if task.get("event_policy_version", 0) >= 2 and not event.get("claims"):
            raise ValueError("New events require atomic claims with their own original evidence and scope")
        if task.get("parent_card_id"):
            depends_on = list(dict.fromkeys([*(depends_on or []), task["parent_card_id"]]))
    if event:
        evidence = unique_refs([*evidence, *(r for c in event.get("claims", []) for r in c["evidence"])])
    dependencies = validate_refs(store, evidence)
    if event:
        from .events import dependencies as event_dependencies
        from .events import validate

        event = validate(store, event)
        dependencies.extend(event_dependencies(event))
    for parent in depends_on or []:
        obj = store.get(parent, "card")
        if obj["status"] in ("stale", "rejected"):
            raise ValueError("Cannot depend on stale/rejected card")
        dependencies.append(parent)
    return store.put(
        "card",
        {
            "statement": statement,
            "card_type": card_type,
            "evidence": evidence,
            "entities": entities or [],
            "time_range": time_range or "unknown",
            "depends_on": depends_on or [],
            **({"task_id": task_id} if task_id else {}),
            **({"followup_task_id": task_id} if task_id and task.get("parent_card_id") else {}),
            "status": "candidate",
            "review_state": "current",
            **({"event": event, "event_schema_version": 1} if event else {}),
        },
        dependencies=dependencies,
        request_key=submission_key,
    )


def revise_card(
    store,
    card_id,
    expected_revision,
    statement,
    evidence,
    reason,
    event=None,
    remove_evidence=None,
    removed_claims=None,
):
    if not statement.strip() or not reason.strip():
        raise ValueError("Statement and revision reason are required")
    with store.transaction() as con:
        card = store.get(card_id, "card", con)
        if card.get("event") and event is None:
            raise ValueError("Use revise_event; do not overwrite a structured event with free text")
        removed = remove_evidence or []
        if any(r not in card["evidence"] for r in removed):
            raise ValueError("Can only remove an existing evidence reference")
        if any(r in evidence for r in removed):
            raise ValueError("Cannot add and remove the same evidence")
        evidence = unique_refs([*(r for r in card["evidence"] if r not in removed), *evidence])
        if event:
            from .events import dependencies as event_dependencies
            from .events import validate

            event = validate(store, event)
            refs = [r for c in event.get("claims", []) for r in c["evidence"]]
            if any(r in refs for r in removed):
                raise ValueError("A retained claim still uses the removed evidence")
            evidence = unique_refs([*evidence, *refs])
        dependencies = validate_refs(store, evidence)
        if event:
            dependencies.extend(event_dependencies(event))
        # Keep explicit inference dependencies; replace evidence dependencies.
        con.execute("DELETE FROM dependencies WHERE child=?", (card_id,))
        for dep in set(dependencies + card["depends_on"]):
            con.execute("INSERT INTO dependencies VALUES (?,?)", (card_id, dep))
        store.assert_live_dependencies(card_id, con)
        return store.update(
            card_id,
            {
                "statement": statement,
                "evidence": evidence,
                "status": "candidate",
                "review": None,
                "revision_reason": reason,
                "evidence_changes": [
                    *card.get("evidence_changes", []),
                    {
                        "at": now(),
                        "reason": reason,
                        "from_revision": card["revision"],
                        "removed": removed,
                        "added": [r for r in evidence if r not in card["evidence"]],
                    },
                ],
                "retired_claims": [
                    *card.get("retired_claims", []),
                    *[
                        {"key": k, **v, "at": now(), "from_revision": card["revision"]}
                        for k, v in (removed_claims or {}).items()
                    ],
                ],
                **({"event": event, "event_schema_version": 1} if event else {}),
            },
            expected_revision=expected_revision,
            invalidate=fact_hash(card)
            != fact_hash(
                {**card, "statement": statement, "evidence": evidence, **({"event": event} if event else {})}
            ),
            con=con,
        )


def review_card(store, card_id, expected_revision, decision, note):
    if decision not in ("reviewed", "rejected") or not note.strip():
        raise ValueError("Human review requires reviewed/rejected and a note")
    card = store.get(card_id, "card")
    if decision == "reviewed":
        validate_refs(store, card["evidence"])
        for dep in card["depends_on"]:
            if store.get(dep, "card")["status"] in ("stale", "rejected"):
                raise ValueError("Resolve invalid dependencies first")
    return store.update(
        card_id,
        {
            "status": decision,
            "review_state": "current",
            "review_causes": {},
            "review": {"actor": "human_cli", "at": now(), "note": note},
        },
        expected_revision=expected_revision,
        invalidate=(decision == "rejected"),
    )


def submit_link(store, from_card, to_card, relation, evidence, inferred=True):
    if from_card == to_card or not relation.strip():
        raise ValueError("Choose distinct cards and explain the relationship")
    for cid in (from_card, to_card):
        if store.get(cid, "card")["status"] in ("stale", "rejected"):
            raise ValueError("Cannot link stale/rejected cards")
    dependencies = validate_refs(store, evidence)
    return store.put(
        "link",
        {
            "from_card": from_card,
            "to_card": to_card,
            "relation": relation,
            "evidence": evidence,
            "inferred": inferred,
            "status": "candidate",
            "review_state": "current",
        },
        dependencies=[from_card, to_card, *dependencies],
    )


def submit_check(
    store,
    question,
    query_ids,
    outcome,
    scope,
    limitations,
    task_id=None,
    decode_run_ids=None,
    body_claim="uninspected",
    body_run_ids=None,
    body_reason="",
):
    if outcome not in ("hits", "zero_hits", "incomplete", "inconclusive"):
        raise ValueError("Unknown check outcome")
    if not question.strip() or not scope.strip() or not limitations.strip():
        raise ValueError("Question, exact scope and limitations are required")
    if outcome in ("hits", "zero_hits") and not query_ids:
        raise ValueError("A conclusive check needs actual queries")
    runs = [store.get(qid, "run") for qid in query_ids]
    if any(r.get("operation") != "query" for r in runs):
        raise ValueError("Checks must reference queries")
    decode_runs = [store.get(rid, "run") for rid in decode_run_ids or []]
    if any(r.get("operation") != "decode" for r in decode_runs):
        raise ValueError("decode_run_ids must reference decoding runs")
    if outcome == "zero_hits" and any(
        r["status"] != "succeeded"
        or r.get("coverage", {}).get("decoded", 0) != r.get("candidate_count")
        or r.get("classified_count") != r.get("candidate_count")
        for r in decode_runs
    ):
        raise ValueError("Unresolved decoding/semantics cannot support zero_hits")
    dependencies = [*query_ids, *(decode_run_ids or []), *(body_run_ids or [])]
    task = None
    if task_id:
        task = active_investigation(store, task_id)
        if any(not set(run["datasets"]).issubset(task["input_ids"]) for run in [*runs, *decode_runs]):
            raise ValueError("Follow-up check used datasets outside the task inputs")
        if task.get("parent_card_id"):
            dependencies.append(task["parent_card_id"])
    from .verification import body_evidence

    body_snapshot = body_evidence(
        store, body_claim, [*(body_run_ids or []), *(decode_run_ids or [])], body_reason, task, outcome
    )
    if outcome in ("hits", "zero_hits"):
        if any(r["status"] != "succeeded" or r["truncated"] for r in runs):
            raise ValueError("Failed/truncated queries cannot support a complete check")
        if any(store.get(did, "dataset")["status"] == "superseded" for r in runs for did in r["datasets"]):
            raise ValueError("Check uses superseded datasets")
        # zero_hits is accepted only for actual zero-row SELECT predicates, not model-interpreted COUNT.
        if outcome == "zero_hits" and any(r["saved_rows"] != 0 for r in runs):
            raise ValueError(
                "zero_hits requires zero returned rows; query the matching rows with a predicate"
            )
        if outcome == "hits" and not any(r["saved_rows"] > 0 for r in runs):
            raise ValueError("hits requires at least one returned row")
    return store.put(
        "check",
        {
            "question": question,
            "query_ids": query_ids,
            "decode_run_ids": decode_run_ids or [],
            "body_claim": body_claim,
            "body_reason": body_reason,
            "body_evidence": body_snapshot,
            "decode_coverage": [
                {
                    "id": r["id"],
                    "revision": r["revision"],
                    "coverage": r.get("coverage", {}),
                    "processed_count": r.get("processed_count"),
                    "candidate_count": r.get("candidate_count"),
                    "classified_count": r.get("classified_count"),
                }
                for r in decode_runs
            ],
            "outcome": outcome,
            "scope": scope,
            "limitations": limitations,
            **({"task_id": task_id} if task_id else {}),
            **({"followup_task_id": task_id} if task_id and task.get("parent_card_id") else {}),
            "status": "candidate",
        },
        dependencies=dependencies,
    )


def active_investigation(store, task_id):
    task = store.get(task_id, "task")
    if task["role"] != "ir-investigate" or task["status"] != "running":
        raise ValueError("Expected a running investigation task")
    return active_followup(store, task_id) if task.get("parent_card_id") else task


def active_followup(store, task_id):
    task = store.get(task_id, "task")
    if not task.get("parent_card_id") or task["status"] != "running":
        raise ValueError("Expected a running follow-up task")
    parent = store.get(task["parent_card_id"], "card")
    if parent_changed(task, parent):
        raise ValueError("Parent card changed; create a follow-up for its current revision")
    return task


def current_followup_review(task, synthesis_task_id, artifacts):
    review = task.get("followup_review") or {}
    return (
        review.get("synthesis_task_id") == synthesis_task_id
        and review.get("artifact_revisions") == {o["id"]: o["revision"] for o in artifacts}
        and all(
            (o.get("status") not in ("stale", "rejected", "superseded") and not pending(o)) or disposed(o)
            for o in artifacts
        )
    )


def create_task(
    store,
    role,
    question,
    scope,
    input_ids,
    parent_card_id=None,
    direction="both",
    verification="",
    requires_body_check=False,
    event_policy_version=0,
):
    if role not in ("ir-prepare", "ir-investigate", "ir-synthesize"):
        raise ValueError("Unknown task role")
    if not question.strip() or not scope.strip():
        raise ValueError("Task needs a concrete question and scope")
    for oid in input_ids:
        store.get(oid)
    # A question about content can require inspection. HTTP metadata alone is not a trigger.
    if type(requires_body_check) is not bool or (requires_body_check and role != "ir-investigate"):
        raise ValueError("requires_body_check is an explicit boolean requirement for investigation tasks")
    followup = {}
    if direction not in ("upstream", "downstream", "both"):
        raise ValueError("Use upstream/downstream/both")
    if parent_card_id:
        if role != "ir-investigate":
            raise ValueError("Card follow-ups must be investigation tasks")
        parent = store.get(parent_card_id, "card")
        if parent["status"] in ("stale", "rejected"):
            raise ValueError("Follow-up needs a current parent card")
        followup = {
            "parent_card_id": parent_card_id,
            "parent_card_revision": parent["revision"],
            "parent_fact_hash": fact_hash(parent),
            "direction": direction,
            "verification": verification,
        }
        for previous in store.all("task"):
            if (
                previous.get("parent_card_id") == parent_card_id
                and previous.get("parent_card_revision") == parent["revision"]
                and previous["question"] == question
                and previous["scope"] == scope
                and previous.get("direction", "both") == direction
                and previous.get("verification", "") == verification
                and previous.get("requires_body_check", False) == requires_body_check
                and set(previous["input_ids"]) == set([*input_ids, parent_card_id])
            ):
                return previous
        input_ids = list(dict.fromkeys([*input_ids, parent_card_id]))
    return store.put(
        "task",
        {
            "role": role,
            "question": question,
            "scope": scope,
            "input_ids": input_ids,
            "status": "pending",
            "summary": "",
            "artifact_ids": [],
            "requires_body_check": requires_body_check,
            "evidence_policy_version": 1,
            "event_policy_version": event_policy_version,
            **followup,
        },
        dependencies=input_ids,
    )


def update_task(
    store, task_id, expected_revision, status, summary="", artifact_ids=None, excluded_artifacts=None
):
    transitions = {
        "pending": {"running", "failed"},
        "running": {"completed", "failed", "partial"},
        "partial": {"running"},
        "failed": {"running"},
        "completed": set(),
    }
    task = store.get(task_id, "task")
    if status not in transitions[task["status"]]:
        raise ValueError(f"Invalid transition {task['status']} -> {status}")
    artifacts = artifact_ids or []
    if status == "partial" and task["role"] != "ir-synthesize":
        raise ValueError("partial is for a synthesis progress report, not completed investigation")
    for oid in artifacts:
        if store.get(oid)["kind"] not in ("dataset", "card", "link", "check", "report", "run"):
            raise ValueError("Task artifact must be data, analysis or run record")
    if status == "completed" and (not artifacts or not summary.strip()):
        raise ValueError("Completion requires summary and real artifact refs (including inconclusive checks)")
    exclusions = dict(task.get("excluded_artifacts", {}))
    for oid, reason in (excluded_artifacts or {}).items():
        obj = store.get(oid)
        if oid in artifacts or obj.get("task_id") != task_id or not reason.strip():
            raise ValueError(
                "Excluded artifacts must belong to this task, have a reason, and not be delivered"
            )
        exclusions[oid] = {"reason": reason, "revision": obj["revision"], "at": now()}
    if status == "completed":
        from .verification import require_ready, task_readiness

        require_ready(task_readiness(store, task_id, artifacts))
    if status == "completed" and task.get("parent_card_id"):
        active_followup(store, task_id)
        items = [store.get(oid) for oid in artifacts]
        checks = [o for o in items if o["kind"] == "check" and o.get("followup_task_id") == task_id]
        cards = [o for o in items if o["kind"] == "card" and o.get("followup_task_id") == task_id]
        if not checks:
            raise ValueError("Follow-up completion requires a current check linked to this task")
        if any(o["outcome"] == "hits" for o in checks) and not cards:
            raise ValueError("A follow-up with hits requires a new evidence card linked to this task")
        if any(o["kind"] in ("card", "check") and o.get("followup_task_id") != task_id for o in items):
            raise ValueError("Card and check artifacts must belong to this follow-up")
    if status == "completed" and task["role"] == "ir-synthesize":
        from .verification import closure_readiness, require_ready

        require_ready(closure_readiness(store))
        if not any(
            store.get(oid)["kind"] == "report" and store.get(oid).get("delivery") == "final"
            for oid in artifacts
        ):
            raise ValueError("Completed synthesis requires a final report; use partial for a progress report")
        for artifact_id in artifacts:
            artifact = store.get(artifact_id)
            if artifact["kind"] == "report" and artifact["status"] == "stale":
                raise ValueError("Generate a current report after recording all reviews")
        for oid in task["input_ids"]:
            followup = store.get(oid)
            if not followup.get("parent_card_id") or followup["status"] != "completed":
                continue
            parent = store.get(followup["parent_card_id"], "card")
            if parent_changed(followup, parent) and not disposed(parent):
                raise ValueError(f"Parent card changed for follow-up {oid}")
            items = [store.get(artifact_id) for artifact_id in followup["artifact_ids"]]
            if not current_followup_review(followup, task_id, items):
                raise ValueError(f"Synthesis must review follow-up {oid} and its current artifacts")
    if status == "partial" and (
        not summary.strip()
        or not any(
            store.get(oid)["kind"] == "report" and store.get(oid).get("delivery") == "progress"
            for oid in artifacts
        )
    ):
        raise ValueError("Partial synthesis needs a progress report and explanation of remaining work")
    return store.update(
        task_id,
        {
            "status": status,
            "summary": summary[:4000],
            "artifact_ids": artifacts,
            "excluded_artifacts": exclusions,
        },
        expected_revision=expected_revision,
    )


def rebase_followup(store, task_id, expected_revision, reason):
    """Explicitly reopen against the current parent; never silently validate old artifacts."""
    task = store.get(task_id, "task")
    if not task.get("parent_card_id") or not reason.strip():
        raise ValueError("A follow-up and revalidation reason are required")
    parent = store.get(task["parent_card_id"], "card")
    if parent["status"] in ("stale", "rejected"):
        raise ValueError("Repair the parent card before rebasing")
    if parent["revision"] == task["parent_card_revision"]:
        raise ValueError("Parent unchanged; revise or exclude stale output artifacts instead")
    return store.update(
        task_id,
        {
            "parent_card_revision": parent["revision"],
            "parent_fact_hash": fact_hash(parent),
            "status": "running",
            "artifact_ids": [],
            "followup_review": None,
            "rebase_history": [
                *task.get("rebase_history", []),
                {
                    "from_revision": task["parent_card_revision"],
                    "to_revision": parent["revision"],
                    "previous_artifact_ids": task["artifact_ids"],
                    "reason": reason,
                    "at": now(),
                },
            ],
        },
        expected_revision=expected_revision,
        invalidate=True,
    )


def review_followup(store, task_id, synthesis_task_id, verdict, note):
    if verdict not in ("supported", "needs_more_evidence") or not note.strip():
        raise ValueError("Choose supported/needs_more_evidence and explain the review")
    with store.transaction() as con:
        synthesis = store.get(synthesis_task_id, "task", con)
        task = store.get(task_id, "task", con)
        if (
            synthesis["role"] != "ir-synthesize"
            or synthesis["status"] != "running"
            or task_id not in synthesis["input_ids"]
        ):
            raise ValueError("Use a running synthesis task that names this follow-up as input")
        if not task.get("parent_card_id") or task["status"] != "completed":
            raise ValueError("Only completed follow-ups can be reviewed")
        parent = store.get(task["parent_card_id"], "card", con)
        if parent_changed(task, parent) and not disposed(parent):
            raise ValueError("The original card changed; re-open the question as a new follow-up")
        artifacts = [store.get(oid, con=con) for oid in task["artifact_ids"]]
        if any(
            (o.get("status") in ("stale", "rejected", "superseded") or pending(o)) and not disposed(o)
            for o in artifacts
        ):
            raise ValueError("Review requires current artifacts")
        review = {
            "synthesis_task_id": synthesis_task_id,
            "verdict": verdict,
            "note": note[:4000],
            "artifact_revisions": {o["id"]: o["revision"] for o in artifacts},
        }
        return store.update(task_id, {"followup_review": review}, invalidate=True, con=con)


def supersede_dataset(store, dataset_id, replacement_id, reason):
    if dataset_id == replacement_id or not reason.strip():
        raise ValueError("Distinct replacement and reason required")
    old, new = store.get(dataset_id, "dataset"), store.get(replacement_id, "dataset")
    if old["status"] == "superseded" or new["status"] == "superseded":
        raise ValueError("Dataset already superseded")
    return store.update(
        dataset_id,
        {"status": "superseded", "replacement_id": replacement_id, "replacement_reason": reason},
        expected_revision=old["revision"],
        invalidate=True,
    )


def case_context(store):
    # Bounded overview; large inventories are fetched through explicit pagination.
    meta = case_metadata(store)
    for field in ("skipped", "errors"):
        meta[f"{field}_count"] = len(meta[field])
        meta[field] = meta[field][:20]

    def brief(obj, fields):
        return {
            key: value[:1000] if isinstance(value, str) else value
            for key, value in obj.items()
            if key in ("id", "revision", *fields)
        }

    return {
        "case": meta,
        "counts": store.counts(),
        "sources": store.list("source", 30),
        "datasets": [
            brief(ds, ("description", "status", "row_count", "sources")) for ds in store.list("dataset", 20)
        ],
        "tasks": [
            brief(task, ("role", "question", "status", "summary", "artifact_ids", "parent_card_id"))
            for task in store.list("task", 30)
        ],
        "source_leads": store.list("source_lead", 20),
        "page_note": "Use list_objects/source_queue for all pages",
        "card_status_counts": {
            s: sum(c["status"] == s for c in store.all("card"))
            for s in ("candidate", "reviewed", "rejected", "stale")
        },
    }


def board_context(store, search="", entity="", status="", offset=0, limit=20):
    if not 1 <= limit <= 50 or offset < 0:
        raise ValueError("Invalid page")
    found = (
        c
        for c in store.all("card")
        if (not search or search.casefold() in dumps(c).casefold())
        and (not entity or entity in c["entities"])
        and (not status or status == c["status"])
    )
    page, total, size, page_full = [], 0, 0, False
    for card in found:
        if offset <= total < offset + limit and not page_full:
            card_size = len(dumps(card))
            if page and size + card_size > 24000:
                page_full = True
            else:
                page.append(card)
                size += card_size
        total += 1
    manifest = store.put(
        "run",
        {
            "operation": "context",
            "status": "succeeded",
            "at": now(),
            "filter": {"search": search, "entity": entity, "status": status},
            "returned": [{"id": c["id"], "revision": c["revision"]} for c in page],
        },
    )
    return {
        "cards": page,
        "total_matching": total,
        "offset": offset,
        "next_offset": offset + len(page) if offset + len(page) < total else None,
        "manifest_id": manifest["id"],
    }
