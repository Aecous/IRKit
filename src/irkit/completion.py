"""Delivery validation for one invocation; exit(0) alone is never delivery."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing


def checkpoint(store):
    with closing(sqlite3.connect(store.db)) as con:
        return {
            "after_event": con.execute("SELECT coalesce(max(seq),0) FROM runtime_events").fetchone()[0],
            "after_change": con.execute("SELECT coalesce(max(seq),0) FROM changes").fetchone()[0],
        }


def assess(store, after_event=0, after_change=0, exit_code=0, until=None):
    """Scope to touched tasks and newly generated reports, never another run's report."""
    with closing(sqlite3.connect(store.db, timeout=30)) as con:
        event_rows = con.execute(
            "SELECT event_type,payload FROM runtime_events WHERE seq>? AND (? IS NULL OR at<=?) "
            "AND event_type IN ('result','session_end','system') ORDER BY seq",
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
    for kind, raw in event_rows:
        p = json.loads(raw)
        if kind == "result":
            result = p
        elif kind == "session_end":
            ending = p
        elif p.get("subtype") == "task_notification" and p.get("status") in ("stopped", "failed"):
            stopped.append(p.get("tool_use_id") or p.get("task_id"))
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
    if any(t.get("event_policy_version") for t in tasks.values()) and not set(syntheses) & native_deliveries:
        reasons.append("未观察到独立综合子 Agent 生成并交付最终报告；主 Agent 自行登记复核不能替代")
    readiness = None
    if any(report.get("delivery") == "final" for report in reports.values()):
        from .verification import closure_readiness

        readiness = closure_readiness(store)
        if not readiness["ready"]:
            reasons.append(f"结案前检查仍有 {len(readiness['issues'])} 个阻塞项")
    if stopped:
        reasons.append(f"{len(stopped)} 个原生子 Agent 被停止或失败")
    if unfinished:
        reasons.append(f"{len(unfinished)} 个本轮任务尚未完成")
    if not reports:
        reasons.append("本轮没有落盘的有效报告")
    if not syntheses:
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
        completion_version=2,
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
    return assess(store, after_event, after_change, job.get("exit_code", 0), job["updated"])
