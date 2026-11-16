"""Small evidence contracts, not an Agent scheduler or a natural-language truth checker."""

from .integrity import delivery_issues, disposed, parent_changed, pending
from .store import dumps

INVALID = {"stale", "rejected", "superseded"}


def body_evidence(store, claim, run_ids, reason="", task=None, outcome="inconclusive"):
    if claim not in {"uninspected", "not_required", "absent", "present"}:
        raise ValueError("body_claim: uninspected/not_required/absent/present")
    if claim == "not_required" and not reason.strip():
        raise ValueError("Explain why this question can be answered without request bodies")
    runs = [store.get(rid, "run") for rid in dict.fromkeys(run_ids)]
    for r in runs:
        if r.get("operation") not in {"decode", "body_inspection"} or r["status"] != "succeeded":
            raise ValueError(f"Body evidence requires completed inspection/decoding: {r['id']}")
        if r.get("processed_count") != r.get("candidate_count"):
            raise ValueError(f"Body processing is incomplete: {r['id']}")
        if any(store.get(did, "dataset")["status"] in INVALID for did in r.get("datasets", [])):
            raise ValueError(f"Body evidence uses outdated datasets: {r['id']}")
        if task:
            sources = set()
            for oid in task["input_ids"]:
                obj = store.get(oid)
                if obj["kind"] == "dataset":
                    sources.update(obj["sources"])
                elif obj["kind"] == "source":
                    sources.add(oid)
            if not set(r.get("datasets", [])).issubset(task["input_ids"]) or not {
                ref["source_id"] for ref in r.get("refs", [])
            }.issubset(sources):
                raise ValueError(f"Body evidence outside task inputs: {r['id']}")
    if claim in {"absent", "present"} and (not runs or not sum(r["candidate_count"] for r in runs)):
        raise ValueError("Body claims require inspected original rows; empty selection is not absence")
    if claim == "absent" and any(
        r.get("coverage", {}).get("absent", 0) != r["candidate_count"] for r in runs
    ):
        raise ValueError("Absent body claim contradicted by present, unreadable or unresolved original rows")
    if claim == "present" and not any(
        r.get("body_presence", {}).get("present", 0)
        or r.get("coverage", {}).get("decoded", 0)
        or any(x.get("body_state") == "present" for x in r.get("records", []))
        or r.get("coverage", {}).get("unresolved", 0)
        or r.get("coverage", {}).get("size_limit", 0)
        for r in runs
    ):
        raise ValueError("No inspected row establishes a present body")
    if outcome == "zero_hits" and claim == "present":
        if not runs or any(
            r.get("operation") != "decode"
            or r.get("coverage", {}).get("decoded", 0) != r["candidate_count"]
            or r.get("classified_count") != r["candidate_count"]
            for r in runs
        ):
            raise ValueError("Body zero_hits needs complete decoded/semantic coverage, not samples")
    return [
        {
            "id": r["id"],
            "revision": r["revision"],
            "operation": r["operation"],
            "selection": r.get("selection", "filtered_all_rows"),
            "datasets": r.get("datasets", []),
            "filters": r.get("filters"),
            "refs": r.get("refs"),
            "body_field": r.get("body_field"),
            "coverage": r.get("coverage", {}),
            "candidate_count": r["candidate_count"],
            "body_presence": r.get("body_presence", {}),
            "processed_count": r["processed_count"],
        }
        for r in runs
    ]


def task_readiness(store, task_id, artifact_ids=None):
    task = store.get(task_id, "task")
    items = [store.get(oid) for oid in (artifact_ids if artifact_ids is not None else task["artifact_ids"])]
    issues = []
    for obj in items:
        if (obj.get("status") in INVALID or pending(obj)) and not disposed(obj):
            issues.append(
                {
                    "code": "STALE_ARTIFACT",
                    "object_id": obj["id"],
                    "kind": obj["kind"],
                    "revision": obj["revision"],
                    "stale_because": obj.get("stale_because"),
                    "action": "Re-read dependencies and revise/recheck, or exclude with an explicit reason",
                }
            )
    if task.get("parent_card_id"):
        parent = store.get(task["parent_card_id"], "card")
        if parent_changed(task, parent) and not disposed(parent):
            issues.append(
                {
                    "code": "PARENT_CHANGED",
                    "object_id": parent["id"],
                    "expected_revision": task["parent_card_revision"],
                    "revision": parent["revision"],
                    "action": "Rebase follow-up to the current valid parent, then recheck affected artifacts",
                }
            )
    checks = [
        o
        for o in items
        if o["kind"] == "check" and o.get("task_id") == task_id and o.get("status") not in INVALID
    ]
    if task.get("requires_body_check") and not any(
        c.get("body_claim", "uninspected") != "uninspected" for c in checks
    ):
        issues.append(
            {
                "code": "BODY_UNINSPECTED",
                "object_id": task_id,
                "action": "Inspect original request bodies and attach a check, or justify not_required for a metadata-only question",
            }
        )
    for check in checks:
        for snapshot in check.get("body_evidence", []):
            run = store.get(snapshot["id"], "run")
            if run["revision"] != snapshot["revision"] or run["status"] != "succeeded":
                issues.append(
                    {
                        "code": "BODY_EVIDENCE_CHANGED",
                        "object_id": check["id"],
                        "action": "Submit a check against current body inspection/decoding coverage",
                    }
                )
    return {"task_id": task_id, "ready": not issues, "issues": issues}


def closure_readiness(store):
    """Check case-wide work, including tasks omitted from synthesis inputs."""
    issues = delivery_issues(store)
    if any(task.get("event_policy_version", 0) >= 4 for task in store.all("task")):
        from .input_coverage import input_coverage

        for source in input_coverage(store):
            if source["state"] not in {"complete", "duplicate"} and not source["gap"]:
                issues.append(
                    dict(
                        code="INPUT_COVERAGE_PENDING",
                        object_id=source["source_id"],
                        state=source["state"],
                        path=source["path"],
                        action="Process remaining input or record an evidence-backed limitation",
                    )
                )
    from .events import event_queue

    offset = 0
    while True:
        page = event_queue(store, 100, offset)
        for question in page["questions"]:
            issues.append(
                {
                    "code": "EVENT_QUESTION_OPEN",
                    "object_id": question["card_id"],
                    "direction": question["direction"],
                    "state": question["state"],
                    "question": question["question"],
                    "task_ids": question["task_ids"],
                    "action": "Investigate/review this event question; only verified visibility limits may be bounded",
                }
            )
        if page["next_offset"] is None:
            break
        offset = page["next_offset"]
    for task in store.all("task"):
        if task["role"] == "ir-synthesize" or (task.get("source_lead_id") and not task.get("parent_card_id")):
            continue
        if task["status"] != "completed":
            issues.append(
                {
                    "code": "UNFINISHED_TASK",
                    "object_id": task["id"],
                    "status": task["status"],
                    "action": "Dispatch/finish the investigation or deliver a progress report only",
                }
            )
            continue
        issues.extend(task_readiness(store, task["id"])["issues"])
        if task.get("parent_card_id"):
            from .board import current_followup_review

            review = task.get("followup_review") or {}
            artifacts = [store.get(oid) for oid in task["artifact_ids"]]
            reviewer = (
                store.get(review["synthesis_task_id"], "task") if review.get("synthesis_task_id") else None
            )
            if (
                not current_followup_review(task, review.get("synthesis_task_id"), artifacts)
                or not reviewer
                or reviewer["status"] == "failed"
            ):
                issues.append(
                    {
                        "code": "FOLLOWUP_UNREVIEWED",
                        "object_id": task["id"],
                        "action": "Review current follow-up evidence in synthesis",
                    }
                )
            elif review.get("verdict") == "needs_more_evidence":
                issues.append(
                    {
                        "code": "FOLLOWUP_NEEDS_EVIDENCE",
                        "object_id": task["id"],
                        "action": "Investigate the unresolved question; supported can acknowledge a verified visibility limit",
                    }
                )
    for run in store.all("run"):
        if run.get("operation") == "decode" and run["status"] == "running":
            issues.append(
                {
                    "code": "DECODING_INCOMPLETE",
                    "object_id": run["id"],
                    "action": "Resume decode_batch or deliver a progress report with unfinished coverage",
                }
            )
    return {"ready": not issues, "issues": issues}


def require_ready(result):
    if not result["ready"]:
        raise ValueError(dumps(result))
