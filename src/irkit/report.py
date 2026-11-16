from __future__ import annotations

import html

from .evidence import case_metadata
from .input_coverage import input_coverage
from .integrity import delivery_snapshot, parent_changed, pending
from .store import dumps, now, review_mode, uid


def safe(text):
    return html.escape(str(text)).replace("`", "&#96;").replace("\n", "<br>")


def followup_section(followups, objects, tasks):
    lines = ["", "### 关键问题补证与复核", ""]
    for task in followups:
        parent = objects.get(task["parent_card_id"])
        review = task.get("followup_review")
        if parent is None or parent_changed(task, parent):
            review_state = "起点卡片已变更，需重新补证"
        elif task["status"] != "completed":
            review_state = "补证未完成"
        elif not review:
            review_state = "待综合复核"
        elif any(
            oid not in objects
            or objects[oid]["revision"] != revision
            or objects[oid]["status"] in ("stale", "rejected")
            for oid, revision in review["artifact_revisions"].items()
        ):
            review_state = "证据修订后待重新复核"
        elif tasks.get(review["synthesis_task_id"], {}).get("status") == "failed":
            review_state = "综合复核任务失败"
        else:
            verdict = {"supported": "证据支持记录的结论", "needs_more_evidence": "仍需补证"}
            review_state = f"{verdict[review['verdict']]}（{review['synthesis_task_id']}） — {review['note']}"
        lines += [
            f"### {task['id']} · {safe(task['question'])}",
            "",
            f"- 起点卡片：`{task['parent_card_id']}` r{task['parent_card_revision']}",
            f"- 追查方向：{safe(task.get('direction', 'both'))}",
            f"- 验证条件：{safe(task.get('verification') or '见任务问题')}",
            f"- 计划范围：{safe(task['scope'])}",
            f"- 任务状态：{safe(task['status'])}",
            f"- 取证结论：{safe(task['summary'] or '尚未交付')}",
            f"- 综合复核：{safe(review_state)}",
        ]
        for oid, exclusion in task.get("excluded_artifacts", {}).items():
            lines.append(f"- 未采纳的历史产物 `{oid}`：{safe(exclusion['reason'])}（历史记录保留）")
        for rebased in task.get("rebase_history", []):
            lines.append(
                f"- 起点版本调整：r{rebased['from_revision']} → r{rebased['to_revision']}；"
                f"{safe(rebased['reason'])}；原产物 {safe(dumps(rebased['previous_artifact_ids']))}"
            )
        attached = [
            o
            for o in objects.values()
            if o.get("followup_task_id") == task["id"]
            and (task["status"] != "completed" or o["id"] in task["artifact_ids"])
        ]
        for obj in attached:
            if obj["kind"] == "check":
                lines += [
                    f"- 排查记录 `{obj['id']}`（{obj['outcome']} / {obj['status']}）：{safe(obj['question'])}",
                    f"  - 实查范围：{safe(obj['scope'])}",
                    f"  - 查询：{safe(', '.join(obj['query_ids']) or '无可执行查询')}",
                    f"  - 解码覆盖：{safe(dumps(obj.get('decode_coverage', [])))}",
                    f"  - 证据缺口：{safe(obj['limitations'])}",
                ]
            else:
                lines.append(f"- 新证据卡片 `{obj['id']}`（{obj['status']}）：{safe(obj['statement'])}")
        if not any(o["kind"] == "check" for o in attached):
            lines.append("- 证据缺口：尚无关联排查记录。")
        lines.append("")
    return lines


def render_report(store, assessment, gaps, next_questions, delivery="final", report_content=None):
    # Hold the case write lock through final validation and publication; concurrent findings cannot
    # slip between delivery review validation and the report dependency snapshot.
    with store.transaction() as con:
        return _render_report(store, assessment, gaps, next_questions, delivery, report_content, con)


def _render_report(store, assessment, gaps, next_questions, delivery, report_content, con):
    if not assessment.strip():
        raise ValueError("Provide a bounded assessment, including inconclusive if appropriate")
    if delivery not in ("final", "progress"):
        raise ValueError("delivery must be final or progress")
    from .verification import closure_readiness, require_ready

    fast = review_mode() == "off"
    readiness = closure_readiness(store)
    # In fast mode, review-only closure blockers (pending re-review, unreviewed follow-ups,
    # unresolved conflicts awaiting synthesis) become warnings carried into the report
    # instead of hard blocks, since the independent synthesis pass is skipped. Evidence
    # contracts remain enforced by the individual tools.
    if delivery == "final" and not fast:
        require_ready(readiness)
        if any(t.get("event_policy_version", 0) >= 2 for t in store.all("task")):
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
    from .report_template import chapters, relation_display, validate

    if report_content is not None:
        report_content = validate(store, report_content)
        if delivery == "final" and any(t.get("event_policy_version", 0) >= 4 for t in store.all("task")):
            from .source_profile import source_issues

            cited_cards = {}
            for section in ("conclusions", "impacts"):
                for finding in report_content[section]:
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
        if (
            not fast
            and (
                not review
                or not current_followup_review(task, review.get("synthesis_task_id"), artifacts)
                or tasks.get(review.get("synthesis_task_id"), {}).get("status") == "failed"
            )
        ):
            raise ValueError(f"Review current follow-up evidence before rendering: {task['id']}")
    rid = uid("report")
    lines = [
        "# 应急响应调查草稿" if delivery == "final" else "# 应急响应阶段报告（调查未完成）",
        "",
        f"案件：{safe(meta['id'])}  生成时间：{now()}",
        "",
        "本报告是阶段性分析。候选、推断和人工审核状态分别标注；缺少证据不等于证明安全。",
        f"交付类型：{delivery}；未决阻塞项：{len(readiness['issues'])}。最终交付也不等同于人工审核通过。",
        *(
            ["复核模式：已关闭独立综合复核（IRKIT_REVIEW_MODE=off），结论未经独立复核，"
             "以下未决项仅作提示，需人工核对。"]
            if fast
            else []
        ),
        *(
            [f"- 未决提示：{issue.get('code')} {issue.get('object_id', '')} — {issue.get('action', '')}"
             for issue in readiness["issues"][:30]]
            if fast and readiness["issues"]
            else []
        ),
        "",
    ]
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
    )
    lines += structured + ["", "### 逐项证据与统计口径（工具生成）", ""]
    for card in cards:
        if card["status"] in ("rejected", "superseded", "stale"):
            lines.append(
                f"- 历史节点 `{card['id']}`：{safe(dumps(card.get('disposition', {'state': '待处置'})))}"
            )
            continue
        for claim in card.get("event", {}).get("claims", []):
            lines += [
                f"- `{card['id']}#{safe(claim['key'])}` [{safe(claim['level'])}] {safe(claim['statement'])}",
                f"  - 范围：{safe(dumps(claim['scope']))}",
                f"  - 证据：{safe(dumps(claim['evidence']))}",
            ]
            if claim.get("statistic_snapshot"):
                lines.append(f"  - 查询单元格与完整口径：{safe(dumps(claim['statistic_snapshot']))}")
        for retired in card.get("retired_claims", []):
            lines.append(f"- `{card['id']}#{safe(retired['key'])}` 已撤销：{safe(retired['reason'])}")
    lines += ["", "### 数据范围与质量", ""]
    if readiness["issues"]:
        lines += ["", "### 未完成事项（工具检查）", ""]
        lines += [f"- {safe(dumps(issue))}" for issue in readiness["issues"]]
    counts = {
        state: sum(row["state"] == state for row in coverage)
        for state in ("complete", "duplicate", "partial", "not_processed", "unverified")
    }
    lines.append(
        f"- 已登记 {len(coverage)} 份；原文引用全覆盖 {counts['complete']}；哈希重复 {counts['duplicate']}；"
        f"部分 {counts['partial']}；未处理 {counts['not_processed']}；覆盖未核验 {counts['unverified']}。"
        "原文引用范围只衡量记录覆盖，字段解析质量另见数据集说明。"
    )
    labels = dict(
        complete="已入库（原文引用范围完整）",
        duplicate="已验证重复",
        partial="部分入库",
        not_processed="尚未数据化（未处理）",
        unverified="已发布，原文覆盖未核验",
    )
    for source, row in zip(sources, coverage):
        lines.append(
            f"- `{source['id']}` {safe(source['original_path'])}；{source['size']} 字节；"
            f"{source['record_kind']}；SHA256 `{source['sha256']}`；"
            f"{labels[row['state']]}；引用的记录 {row['referenced_records'] if row['referenced_records'] is not None else '未知'} / "
            f"{row['records'] if row['records'] is not None else '未知'}；分区 {safe(', '.join(row['dataset_ids']) or '无')}"
            + (f"；与 `{row['duplicate_of']}` 哈希相同" if row["duplicate_of"] else "")
            + (
                f"；覆盖缺口：{safe(row['gap']['reason'])}；依据 {safe(', '.join(row['gap']['attempt_ids']))}"
                if row["gap"] and row["state"] not in {"complete", "duplicate"}
                else ""
            )
        )
    for ds in datasets:
        lines.append(f"- 数据集 `{ds['id']}`：{ds['row_count']} 行；{ds['status']}；{safe(ds['quality'])}")
    for item in meta["skipped"] + meta["errors"]:
        lines.append(f"- 输入缺口：{safe(item['path'])}：{safe(item['reason'])}")
    if followups:
        objects = {o["id"]: o for o in [*cards, *checks, *links]}
        for task in followups:
            for oid in task["artifact_ids"]:
                if oid not in objects:
                    objects[oid] = store.get(oid)
        lines += followup_section(followups, objects, tasks)
    lines += ["", "### 证据卡片", ""]
    for card in cards:
        from .events import report_lines

        content = "\n".join(report_lines(card)) if card.get("event") else card["statement"]
        lines += [
            f"### {card['id']} · {card['card_type']} · {card['status']} · r{card['revision']}",
            "",
            safe(content),
            "",
            f"时间：{safe(card['time_range'])}",
            "",
            f"证据引用：{safe(dumps(card['evidence']))}",
            f"复核状态：{safe(card.get('review_state', 'legacy'))}；变更原因：{safe(dumps(card.get('review_causes', {})))}",
            f"处置与迁移：{safe(dumps(card.get('disposition', {})))}",
            "",
        ]
    if not cards:
        lines += ["尚无证据卡片。", ""]
    lines += ["### 行为关系（候选图，不自动等同于攻击链）", "", "```mermaid", "flowchart LR"]
    active = {
        c["id"]: c for c in cards if c["status"] not in ("stale", "rejected", "superseded") and not pending(c)
    }
    for cid, card in active.items():
        label = html.escape(f"{card['card_type']} / {card['status']} / {card['statement'][:90]}", quote=True)
        label = label.replace("\n", " ").replace("`", "&#96;")
        lines.append(f'    {cid}["{label}"]')
    for link in links:
        if (
            link["status"] in ("stale", "rejected", "superseded")
            or pending(link)
            or any(link[k] not in active for k in ("from_card", "to_card"))
        ):
            continue
        arrow, label = relation_display(link)
        arrow = ("-.->" if link["inferred"] else "-->") if arrow == "→" else "---"
        lines.append(f"    {link['from_card']} {arrow}|{label}| {link['to_card']}")
    lines += ["```", "", "箭头只用于时序及因果方向。正文与下方记录标注每条关系的证据层级。", ""]
    for link in links:
        lines.append(
            f"- `{link['id']}` {link['from_card']} {relation_display(link)[0]} {link['to_card']}：{safe(link['relation'])}；"
            f"{link['status']}；证据 {safe(dumps(link['evidence']))}"
        )
    lines += ["", "### 排查范围", ""]
    for check in checks:
        lines.append(
            f"- `{check['id']}` {safe(check['question'])}：{check['outcome']} / {check['status']}；"
            f"范围：{safe(check['scope'])}；限制：{safe(check['limitations'])}；"
            f"查询：{safe(', '.join(check['query_ids']))}；"
            f"请求体检查：{safe(check.get('body_claim', 'uninspected'))}；"
            f"不检查理由：{safe(check.get('body_reason', ''))}；"
            f"原文检查/解码覆盖：{safe(dumps(check.get('body_evidence', [])))}"
        )
    failed = [
        r
        for r in store.all("run")
        if r["operation"] in ("query", "transform") and (r["status"] != "succeeded" or r.get("truncated"))
    ]
    lines += ["", "### 不完整执行", ""]
    lines += [
        f"- `{r['id']}` {r['operation']}：{r['status']}；truncated={r.get('truncated', False)}"
        for r in failed
    ]
    lines += ["", "### 缺口与下一步", ""]
    lines += [f"- 缺口：{safe(gap)}" for gap in gaps]
    lines += [f"- 待验证：{safe(question)}" for question in next_questions]
    path = store.root / "reports" / f"{rid}.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return store.put(
        "report",
        {
            "path": f"reports/{rid}.md",
            "status": "draft",
            "delivery": delivery,
            "readiness": readiness,
            "assessment": assessment,
            "template_version": 1,
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
