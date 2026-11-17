from __future__ import annotations

import os

from .evidence import case_metadata
from .input_coverage import input_coverage
from .integrity import delivery_snapshot, parent_changed
from .store import dumps, now, review_mode, uid


def render_report(store, assessment, gaps, next_questions, delivery="final", report_content=None):
    # Hold the case write lock through final validation and publication; concurrent findings cannot
    # slip between delivery review validation and the report dependency snapshot.
    with store.transaction() as con:
        return _render_report(store, assessment, gaps, next_questions, delivery, report_content, con)


def _render_report(store, assessment, gaps, next_questions, delivery, report_content, con):
    report_only = os.environ.get("IRKIT_TASK_MODE") == "report"
    if report_only:
        delivery = "progress"
        if report_content is None:
            raise ValueError("Report-only task requires complete five-chapter report_content")
    if not assessment.strip():
        raise ValueError("Provide a bounded assessment, including inconclusive if appropriate")
    if delivery not in ("final", "progress"):
        raise ValueError("delivery must be final or progress")
    from .verification import closure_readiness, require_ready

    fast = review_mode() == "off"
    readiness = closure_readiness(store)
    if delivery == "final":
        require_ready(readiness)
        if not fast and any(t.get("event_policy_version", 0) >= 2 for t in store.all("task")):
            snapshot = delivery_snapshot(store)
            reviews = [
                r
                for r in store.all("run")
                if r.get("operation") == "delivery_review"
                and r.get("snapshot") == snapshot
                and store.get(r["synthesis_task_id"], "task")["status"] == "running"
            ]
            if not reviews:
                raise ValueError(
                    "DELIVERY_UNREVIEWED: review_delivery must cover current cards and links before final report"
                )
    from .report_template import chapters, findings_in, validate

    if report_content is not None:
        report_content = validate(store, report_content, require_narrative=delivery == "final" or report_only)
        if delivery == "final" and any(t.get("event_policy_version", 0) >= 4 for t in store.all("task")):
            from .source_profile import source_issues

            cited_cards = {}
            for _, finding in findings_in(report_content):
                for ref in finding["evidence"]:
                    item = store.get(ref["object_id"])
                    if item["kind"] == "card":
                        cited_cards[item["id"]] = item
                    elif item["kind"] == "link":
                        for cid in (item["from_card"], item["to_card"]):
                            cited_cards[cid] = store.get(cid, "card")
            if issues := source_issues(store, cited_cards.values()):
                raise ValueError(dumps(issues))
    if (
        delivery == "final"
        and any(t.get("event_policy_version", 0) >= 3 for t in store.all("task"))
        and report_content is None
    ):
        raise ValueError(
            "Five-chapter final report requires structured report_content with cited conclusions and impacts"
        )
    meta = case_metadata(store)
    cards, links, checks = list(store.all("card")), list(store.all("link")), list(store.all("check"))
    datasets = list(store.all("dataset"))
    sources = list(store.all("source"))
    coverage = input_coverage(store, sources, datasets)
    input_gaps = [row["gap"] for row in coverage if row["gap"]]
    tasks = {task["id"]: task for task in store.all("task")}
    followups = [task for task in tasks.values() if task.get("parent_card_id")]
    from .board import current_followup_review

    for task in followups:
        if delivery == "progress":
            continue
        if task["status"] != "completed":
            continue
        review = task.get("followup_review") or {}
        artifacts = [store.get(oid) for oid in task["artifact_ids"]]
        parent = store.get(task["parent_card_id"], "card")
        # A previous revision remains visible as an explicit historical gap;
        # it cannot be reviewed against the new parent and must not block new work forever.
        if parent_changed(task, parent):
            continue
        if not fast and (
            not review
            or not current_followup_review(task, review.get("synthesis_task_id"), artifacts)
            or tasks.get(review.get("synthesis_task_id"), {}).get("status") == "failed"
        ):
            raise ValueError(f"Review current follow-up evidence before rendering: {task['id']}")
    from .report_evidence import evidence_appendix
    from .report_export import write_html_pair

    rid = uid("report")
    path = store.root / "reports" / f"{rid}.md"
    appendix = path.with_name(f"{rid}.evidence.md")
    lines = [
        "# 应急响应调查报告",
        "",
        f"生成时间：{now()}",
        "",
        "报告依据本次已取得的日志与分析结果编写，结论限于文中说明的范围。",
        "",
    ]
    if fast or report_only:
        lines += ["报告未经独立综合复核。", ""]
    structured, evidence_labels = chapters(
        store,
        meta,
        assessment,
        report_content,
        cards,
        links,
        checks,
        datasets,
        gaps,
        next_questions,
        coverage,
        appendix_name=appendix.name,
    )
    lines += structured
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    appendix.write_text(evidence_appendix(store, report_content, evidence_labels, coverage), encoding="utf-8")
    path.chmod(0o600)
    appendix.chmod(0o600)
    write_html_pair(path, appendix)
    return store.put(
        "report",
        {
            "path": f"reports/{rid}.md",
            "appendix_path": f"reports/{rid}.evidence.md",
            "html_path": f"reports/{rid}.html",
            "appendix_html_path": f"reports/{rid}.evidence.html",
            "status": "generated" if delivery == "final" or report_only else "draft",
            "task_mode": "report" if report_only else "investigation",
            "delivery": delivery,
            "review_mode": readiness["review_mode"],
            "human_review_status": "pending",
            "readiness": readiness,
            "assessment": assessment,
            "template_version": 2,
            "report_content": report_content,
            "evidence_labels": evidence_labels,
            "gaps": gaps,
            "next_questions": next_questions,
            "created": now(),
            "snapshot": [
                {"id": o["id"], "revision": o["revision"]}
                for o in cards + links + checks + datasets + followups + input_gaps
            ],
        },
        object_id=rid,
        con=con,
        dependencies=[o["id"] for o in cards + links + checks + datasets + followups + input_gaps],
    )
