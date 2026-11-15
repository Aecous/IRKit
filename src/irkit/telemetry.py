"""Append-only runtime events. SQLite IDs support browser reconnects."""

from __future__ import annotations

import json
import re
import sqlite3
from contextlib import closing

from .store import dumps, now


def initialize(store):
    with closing(sqlite3.connect(store.db, timeout=30)) as con:
        con.execute("""CREATE TABLE IF NOT EXISTS runtime_events (
            seq INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL,
            run_id TEXT, session_id TEXT, agent_id TEXT, task_id TEXT,
            event_type TEXT NOT NULL, payload TEXT NOT NULL)""")
        con.execute("""CREATE TABLE IF NOT EXISTS runtime_links (
            run_id TEXT, tool_id TEXT, task_id TEXT, PRIMARY KEY(run_id,tool_id))""")
        con.execute("CREATE INDEX IF NOT EXISTS runtime_by_run ON runtime_events(run_id,seq)")
        con.commit()


def record(store, run_id, event):
    payload = dict(event)
    parent = payload.get("parent_tool_use_id")
    task_id = payload.get("task_id")
    agent_id = payload.get("agent_id") or parent or "main"
    message = payload.get("message") or {}
    blocks = message.get("content", []) if isinstance(message, dict) else []
    blocks = blocks if isinstance(blocks, list) else []
    with closing(sqlite3.connect(store.db, timeout=30)) as con:
        if parent:
            previous = con.execute(
                "SELECT task_id FROM runtime_links WHERE run_id=? AND tool_id=?", (run_id, parent)
            ).fetchone()
            if previous:
                task_id = previous[0]
        for block in blocks:
            if block.get("type") == "tool_use":
                inputs = block.get("input") or {}
                candidate = inputs.get("task_id")
                if block.get("name") in ("Agent", "Task"):
                    found = re.search(r"task_[0-9a-f]{16}", inputs.get("prompt", ""))
                    candidate = found[0] if found else candidate
                if (
                    candidate
                    and con.execute(
                        "SELECT 1 FROM objects WHERE id=? AND kind='task'", (candidate,)
                    ).fetchone()
                ):
                    task_id = candidate
                if block.get("id") and task_id:
                    con.execute(
                        "INSERT OR REPLACE INTO runtime_links VALUES (?,?,?)", (run_id, block["id"], task_id)
                    )
            if block.get("type") == "tool_result":
                previous = con.execute(
                    "SELECT task_id FROM runtime_links WHERE run_id=? AND tool_id=?",
                    (run_id, block.get("tool_use_id")),
                ).fetchone()
                if previous:
                    task_id = previous[0]
        if not task_id and agent_id != "main":
            previous = con.execute(
                "SELECT task_id FROM runtime_events WHERE run_id=? AND agent_id=? AND task_id IS NOT NULL ORDER BY seq DESC LIMIT 1",
                (run_id, agent_id),
            ).fetchone()
            if previous:
                task_id = previous[0]
        con.execute(
            "INSERT INTO runtime_events(at,run_id,session_id,agent_id,task_id,event_type,payload) VALUES (?,?,?,?,?,?,?)",
            (
                now(),
                run_id,
                payload.get("session_id"),
                agent_id,
                task_id,
                payload.get("type", "unknown"),
                dumps(payload),
            ),
        )
        con.commit()


def events(store, after=0, limit=100):
    with closing(sqlite3.connect(store.db, timeout=30)) as con:
        con.row_factory = sqlite3.Row
        if not con.execute("SELECT 1 FROM sqlite_master WHERE name='runtime_events'").fetchone():
            return []
        rows = con.execute(
            "SELECT * FROM runtime_events WHERE seq>? ORDER BY seq LIMIT ?", (after, limit)
        ).fetchall()
        return [{**dict(r), "payload": json.loads(r["payload"])} for r in rows]


def sessions(store):
    with closing(sqlite3.connect(store.db, timeout=30)) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute("""SELECT run_id,min(at) AS started,max(at) AS updated,
            min(seq) AS first_seq,max(seq) AS last_seq,count(*) AS event_count,
            max(CASE WHEN event_type='session_end' THEN payload END) AS ending
            FROM runtime_events GROUP BY run_id ORDER BY min(seq) DESC""").fetchall()
        return [{**dict(r), "ending": json.loads(r["ending"]) if r["ending"] else None} for r in rows]


def history(store, run_id, before=None, limit=100, agent_id=None):
    aliases = agent_aliases(context(store, run_id)) if agent_id else {}
    canonical = aliases.get(agent_id, agent_id)
    ids = sorted({canonical, *[k for k, v in aliases.items() if v == canonical]}) if agent_id else []
    with closing(sqlite3.connect(store.db, timeout=30)) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute(
            "SELECT * FROM runtime_events WHERE run_id=? AND seq<?"
            + (" AND agent_id IN (" + ",".join("?" for _ in ids) + ")" if ids else "")
            + " ORDER BY seq DESC LIMIT ?",
            (run_id, before if before is not None else 9223372036854775807, *ids, limit),
        ).fetchall()
        return [{**dict(r), "payload": json.loads(r["payload"])} for r in reversed(rows)]


def context(store, run_id):
    """Compact lifecycle index including resumed workers and terminal states."""
    with closing(sqlite3.connect(store.db, timeout=30)) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute(
            "SELECT seq,at,agent_id,event_type,payload FROM runtime_events WHERE run_id=? "
            "AND (event_type IN ('assistant','user','result','session_end') "
            "OR json_extract(payload,'$.subtype') IN ('task_started','task_notification','task_progress')) ORDER BY seq",
            (run_id,),
        ).fetchall()
    result, calls, progress = [], set(), {}
    for row in rows:
        event = dict(row)
        payload = json.loads(event["payload"])
        subtype = payload.get("subtype")
        if subtype in ("task_started", "task_notification", "task_progress"):
            event["payload"] = {
                k: v
                for k, v in payload.items()
                if k
                in (
                    "subtype",
                    "task_id",
                    "tool_use_id",
                    "subagent_type",
                    "description",
                    "status",
                    "last_tool_name",
                )
            }
            if subtype == "task_progress":
                progress[payload.get("tool_use_id")] = event
            else:
                result.append(event)
            continue
        if event["event_type"] in ("session_end", "result"):
            event["payload"] = {k: v for k, v in payload.items() if k in ("exit_code", "is_error", "outcome")}
            result.append(event)
            continue
        blocks = payload.get("message", {}).get("content", [])
        keep = []
        for b in blocks if isinstance(blocks, list) else []:
            if b.get("type") == "tool_use" and b.get("name") in ("Agent", "Task", "SendMessage"):
                calls.add(b["id"])
                inp = b.get("input", {})
                brief = {
                    k: v
                    for k, v in inp.items()
                    if k in ("subagent_type", "description", "run_in_background", "to", "summary")
                }
                brief["prompt"] = " ".join(
                    re.findall(r"task_[0-9a-f]{16}", inp.get("prompt", inp.get("message", "")))[:1]
                )
                keep.append({**b, "input": brief})
            elif b.get("type") == "tool_result" and b.get("tool_use_id") in calls:
                raw = dumps(b.get("content", ""))
                keep.append(
                    {
                        **b,
                        "content": "Async agent launched"
                        if re.search("Async agent launched|working in the background", raw)
                        else "Worker call returned",
                    }
                )
        if keep:
            event["payload"] = {"message": {"content": keep}}
            result.append(event)
    return sorted([*result, *progress.values()], key=lambda e: e["seq"])


def agent_aliases(events):
    aliases, native = {}, {}
    for e in events:
        p = e["payload"]
        if p.get("subtype") == "task_started" and p.get("tool_use_id"):
            tid, call = p.get("task_id"), p["tool_use_id"]
            canonical = native.get(tid, call)
            if tid:
                native[tid] = canonical
            aliases[call] = canonical
    return aliases
