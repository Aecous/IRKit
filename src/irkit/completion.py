"""Delivery validation for one invocation; exit(0) alone is never delivery."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing

from .store import review_mode as configured_review_mode


def checkpoint(store, task_mode="investigation"):
    with closing(sqlite3.connect(store.db)) as con:
        return {
            "review_mode": configured_review_mode(),
            "task_mode": task_mode,
            "after_event": con.execute("SELECT coalesce(max(seq),0) FROM runtime_events").fetchone()[0],
            "after_change": con.execute("SELECT coalesce(max(seq),0) FROM changes").fetchone()[0],
        }


def assess(
    store, after_event=0, after_change=0, exit_code=0, until=None, review_mode=None, task_mode="investigation"
):
    """Scope to touched tasks and newly generated reports, never another run's report."""
    with closing(sqlite3.connect(store.db, timeout=30)) as con:
        event_rows = con.execute(
            "SELECT event_type,payload FROM runtime_events WHERE seq>? AND (? IS NULL OR at<=?) "
            "AND event_type IN ('session_start','result','session_end','system') ORDER BY seq",
            (after_event, until, until),
        ).fetchall()
        changed = con.execute(
            "SELECT DISTINCT o.id,o.kind,o.data,c.action FROM changes c JOIN objects o ON o.id=c.object_id "
            "WHERE c.seq>? AND (? IS NULL OR c.at<=?) AND o.kind IN ('task','report')",
            (after_change, until, until),
        ).fetchall()
        linked = con.execute(
            "SELECT DISTINCT task_id FROM runtime_events WHERE seq>? AND (? IS NULL OR at<=?) "
            "AND task_id IS NOT NULL",
            (after_event, until, until),
        ).fetchall()
        assistant_rows = con.execute(
            "SELECT agent_id,payload FROM runtime_events WHERE seq>? AND (? IS NULL OR at<=?) "
            "AND event_type='assistant' ORDER BY seq",
            (after_event, until, until),
        ).fetchall()
    tasks, reports = {}, {}
    for oid, kind, raw, action in changed:
        obj = {**json.loads(raw), "id": oid}
        if kind == "task":
            tasks[oid] = obj
        elif action == "create" and obj.get("status") not in ("stale", "rejected"):
            try:
                if store.path(obj["path"]).is_file() and store.path(obj["path"]).stat().st_size:
                    reports[oid] = obj
            except (ValueError, KeyError, OSError):
                pass
    for (tid,) in linked:
        try:
            tasks[tid] = store.get(tid, "task")
        except ValueError:
            pass  # Native Claude background task ids are not evidence-board tasks.
    result, ending, stopped = None, None, []
    recorded_mode = None
    for kind, raw in event_rows:
        p = json.loads(raw)
        if kind == "session_start":
            recorded_mode = p.get("review_mode")
            task_mode = p.get("task_mode", task_mode)
        elif kind == "result":
            result = p
        elif kind == "session_end":
            ending = p
        elif p.get("subtype") == "task_notification" and p.get("status") in ("stopped", "failed"):
            stopped.append(p.get("tool_use_id") or p.get("task_id"))
    mode = recorded_mode or review_mode or ("full" if until else configured_review_mode())
    report_only = task_mode == "report"
    fast = mode == "off" or report_only
    final_reports = {rid: r for rid, r in reports.items() if r.get("delivery", "final") == "final"}
    if report_only:
        from .report_template import validate

        final_reports = {}
        for rid, item in reports.items():
            if item.get("task_mode") != "report" or item.get("template_version") != 2:
                continue
            try:
                validate(store, item.get("report_content"), require_narrative=True)
                if all(
                    store.path(item[key]).is_file() and store.path(item[key]).stat().st_size
                    for key in ("path", "appendix_path", "html_path", "appendix_html_path")
                ):
                    final_reports[rid] = item
            except (ValueError, TypeError, KeyError, OSError):
                continue
    unfinished = [
        t["id"]
        for t in tasks.values()
        if t.get("status") != "completed" and not (t.get("source_lead_id") and not t.get("parent_card_id"))
    ]
    syntheses = [
        t["id"]
        for t in tasks.values()
        if t.get("role") == "ir-synthesize"
        and t.get("status") == "completed"
        and any(
            reports[rid].get("delivery", "final") == "final"
            for rid in set(t.get("artifact_ids", [])) & reports.keys()
        )
    ]
    reasons = []
    native_syntheses, renderers, native_deliveries = set(), set(), set()
    for actor, raw in assistant_rows:
        blocks = json.loads(raw).get("message", {}).get("content", [])
        for block in blocks if isinstance(blocks, list) else []:
            if not isinstance(block, dict) or block.get("type") != "tool_use":
                continue
            name, inputs = block.get("name"), block.get("input") or {}
            if name in ("Agent", "Task") and inputs.get("subagent_type") == "ir-synthesize":
                native_syntheses.add(block.get("id"))
            if actor in native_syntheses:
                if name == "mcp__ir__render_report" and inputs.get("delivery", "final") == "final":
                    renderers.add(actor)
                if (
                    name == "mcp__ir__update_task"
                    and inputs.get("status") == "completed"
                    and actor in renderers
                ):
                    native_deliveries.add(inputs.get("task_id"))
    if (
        not fast
        and any(t.get("event_policy_version") for t in tasks.values())
        and not set(syntheses) & native_deliveries
    ):
        reasons.append("未观察到独立综合子 Agent 生成并交付最终报告；主 Agent 自行登记复核不能替代")
    readiness = None
    # Legacy artifacts without a delivery field predate case-wide closure gates.
    if not report_only and any(r.get("delivery") == "final" for r in final_reports.values()):
        from .verification import closure_readiness

        readiness = closure_readiness(store, mode=mode)
        if not readiness["ready"]:
            reasons.append(f"交付检查仍有 {len(readiness['blockers'])} 个阻塞项；证据局限与待复核项另列")
        if any(r.get("review_mode", mode) != mode for r in final_reports.values()):
            reasons.append("报告复核模式与本轮会话不一致，需要按本轮模式重新生成")
    if stopped:
        reasons.append(f"{len(stopped)} 个原生子 Agent 被停止或失败")
    if unfinished:
        reasons.append(f"{len(unfinished)} 个本轮任务尚未完成")
    if not final_reports:
        reasons.append(
            "本轮未生成完整、引用有效的结果报告"
            if report_only
            else "本轮没有落盘的有效最终报告；阶段报告不算完成交付"
        )
    if not fast and not syntheses:
        reasons.append("综合复核任务尚未交付本轮报告")
    if result is None:
        reasons.append("未收到模型会话结果")
    if ending and (ending.get("capture_errors") or ending.get("capture_incomplete")):
        reasons.append("会话记录不完整")
    status = "incomplete" if reasons else "completed"
    if result and result.get("is_error"):
        status = "failed"
        reasons.insert(0, "模型会话失败：" + str(result.get("subtype", "unknown")))
    elif ending and ending.get("reason") in ("timeout", "interrupted"):
        status = "interrupted"
        reasons.insert(0, "会话超时或被中断")
    elif exit_code:
        status = "failed"
        reasons.insert(0, f"执行进程退出码 {exit_code}")
    return dict(
        status=status,
        error="；".join(reasons),
        report_ids=list(reports),
        unfinished_task_ids=unfinished,
        stopped_agent_ids=stopped,
        synthesis_task_ids=syntheses,
        native_synthesis_task_ids=sorted(t for t in native_deliveries if t),
        task_ids=list(tasks),
        closure_readiness=readiness,
        review_mode=mode,
        task_mode=task_mode,
        warnings=readiness["warnings"] if readiness else [],
        completion_version=3,
    )


def legacy_assessment(store, job):
    """Bound old jobs to their own time window; retain original status for audit."""
    with closing(sqlite3.connect(store.db)) as con:
        after_event = con.execute(
            "SELECT coalesce(max(seq),0) FROM runtime_events WHERE at<?", (job["created"],)
        ).fetchone()[0]
        after_change = con.execute(
            "SELECT coalesce(max(seq),0) FROM changes WHERE at<?", (job["created"],)
        ).fetchone()[0]
    return assess(
        store,
        after_event,
        after_change,
        job.get("exit_code", 0),
        job["updated"],
        review_mode=job.get("review_mode"),
    )
