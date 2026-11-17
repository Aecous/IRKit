"""Compact evidence appendix for the citations actually used in a report."""

import json
import re
from contextlib import ExitStack
from pathlib import Path

import duckdb

from .report_template import findings_in, prose


def evidence_appendix(store, content, labels, coverage):
    selected = {}
    for _, finding in findings_in(content or {}):
        for ref in finding["evidence"]:
            selected.setdefault(ref["object_id"], {})[ref.get("claim_key")] = ref
    lines = ["# 证据明细附录", "", "编号与调查报告正文对应。仅列出正文实际引用的证据及回查位置。", ""]
    with ExitStack() as stack:
        connections = {}
        seen_queries = set()

        def raw_locations(refs):
            out = []
            seen = set()
            for ref in refs:
                raw = []
                if ref.get("source_id"):
                    raw = [ref]
                elif ref.get("dataset_id"):
                    ds = store.get(ref["dataset_id"], "dataset")
                    key = ds["id"]
                    if key not in connections:
                        connections[key] = stack.enter_context(
                            duckdb.connect(str(store.path(ds["path"])), read_only=True)
                        )
                    row = (
                        connections[key]
                        .execute("SELECT _refs FROM events WHERE _row_id=?", [ref["row_id"]])
                        .fetchone()
                    )
                    if not row:
                        raise ValueError("Cited dataset row no longer exists")
                    raw = row[0]
                    out.append(f"- 数据定位：`{key}`，第 {ref['row_id']} 行。")
                for location in raw:
                    key = (location["source_id"], location["start"], location["end"])
                    if key in seen:
                        continue
                    seen.add(key)
                    source = store.get(location["source_id"], "source")
                    unit = "文件内记录序号" if source["record_kind"] == "evtx" else "原始行号"
                    out += [
                        f"- 原件：{prose(source['original_path'])}",
                        f"  - 引用：`{source['id']}`；{unit} {location['start']}–{location['end']}。",
                        f"  - SHA-256：`{source['sha256']}`。",
                    ]
                if ref.get("query_id"):
                    out.extend(query_details(ref["query_id"]))
            return out

        def query_details(query_id):
            if query_id in seen_queries:
                return [f"- 查询 `{query_id}`：明细见本附录首次引用位置。"]
            seen_queries.add(query_id)
            run = store.get(query_id, "run")
            sql = run.get("sql", "")
            fence = "`" * max(3, max((len(x) for x in re.findall(r"`+", sql)), default=0) + 1)
            return [
                f"- 查询 `{query_id}`；保存 {run.get('saved_rows', '未知')} 行；"
                f"截断：{'是' if run.get('truncated') else '否'}。",
                f"  - 数据范围：{prose(', '.join(run.get('datasets', [])))}",
                "",
                fence + "sql",
                sql,
                fence,
                "",
            ]

        for oid, refs in selected.items():
            obj = store.get(oid)
            lines += [f"## {labels[oid]}", "", f"证据记录：`{oid}`，版本 {obj['revision']}。", ""]
            if obj["kind"] == "card":
                claims = obj.get("event", {}).get("claims", [])
                chosen = [c for c in claims if c["key"] in refs]
                if not chosen:
                    lines += [prose(obj.get("event", {}).get("observed", obj["statement"])), ""]
                    lines += raw_locations(obj.get("evidence", []))
                for claim in chosen:
                    lines += [
                        f"### {prose(claim['key'])}",
                        "",
                        prose(claim["statement"]),
                        "",
                        "- 证据层级：" + prose(claim["level"]),
                        "- 适用范围：" + prose(json.dumps(claim["scope"], ensure_ascii=False)),
                        "",
                    ]
                    lines += raw_locations(claim["evidence"])
                    if claim.get("statistic_snapshot"):
                        lines += [
                            "统计口径：",
                            "",
                            "```json",
                            json.dumps(claim["statistic_snapshot"], ensure_ascii=False, indent=2),
                            "```",
                            "",
                        ]
            elif obj["kind"] == "check":
                lines += [
                    prose(obj["question"]),
                    "",
                    "- 已查范围：" + prose(obj["scope"]),
                    "- 结果：" + prose(obj.get("conclusion") or obj["outcome"]),
                    "- 限制：" + prose(obj["limitations"]),
                    "",
                ]
                for qid in obj.get("query_ids", []):
                    lines += query_details(qid)
            else:
                lines += [
                    prose(obj["relation"]),
                    "",
                    "- 关联性质：" + prose(obj.get("relation_type", "association")),
                    "- 是否推断：" + ("是" if obj.get("inferred") else "否"),
                    "",
                ]
                lines += raw_locations(obj.get("evidence", []))
            lines += [""]
    if not selected:
        lines += ["本报告尚无具体证据引用；不能据此确认攻击行为。", ""]
    # Summary, not hundreds of machine-generated inventory lines. Original inventory remains local.
    counts = {
        state: sum(r["state"] == state for r in coverage)
        for state in ("complete", "duplicate", "partial", "not_processed", "unverified")
    }
    lines += [
        "## 输入范围说明",
        "",
        f"登记 {len(coverage)} 份输入；原文覆盖完整 {counts['complete']} 份；"
        f"已验证重复 {counts['duplicate']} 份；部分覆盖 {counts['partial']} 份；"
        f"尚未数据化 {counts['not_processed']} 份；覆盖未核验 {counts['unverified']} 份。",
        "",
        "覆盖按原件记录范围统计，不等同于所有字段均已解析或所有行为均已解释。",
        "",
    ]
    for row in coverage:
        if row.get("gap") and row["state"] not in {"complete", "duplicate"}:
            lines += ["- " + prose(Path(row["path"]).name) + "：" + prose(row["gap"]["reason"])]
    return "\n".join(lines) + "\n"
