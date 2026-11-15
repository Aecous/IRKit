"""Five fixed chapters with validated citations; semantics remain independently reviewed."""

import html
from datetime import datetime
from typing import Literal, NotRequired, TypedDict

from .integrity import pending
from .source_leads import aggregate, card_sources


class Citation(TypedDict):
    object_id: str
    revision: int
    claim_key: NotRequired[str]


class Finding(TypedDict):
    text: str
    certainty: Literal["confirmed", "possible", "unknown"]
    evidence: list[Citation]


class ReportInput(TypedDict):
    scope_note: str
    conclusions: list[Finding]
    impacts: list[Finding]
    recommendations: list[Finding]


def clean(value):
    return (
        html.escape(str(value), quote=True).replace("|", "&#124;").replace("`", "&#96;").replace("\n", "<br>")
    )


def validate(store, content):
    if set(content) != {"scope_note", "conclusions", "impacts", "recommendations"}:
        raise ValueError("report_content requires scope_note, conclusions, impacts, recommendations")
    if (
        not isinstance(content["scope_note"], str)
        or not content["scope_note"].strip()
        or len(content["scope_note"]) > 6000
    ):
        raise ValueError("Provide bounded report scope_note")
    for section in ("conclusions", "impacts", "recommendations"):
        rows = content[section]
        if not isinstance(rows, list) or not rows or len(rows) > 50:
            raise ValueError(f"{section}: supply 1..50 findings, including explicit unknown if needed")
        for finding in rows:
            if set(finding) != {"text", "certainty", "evidence"} or finding["certainty"] not in (
                "confirmed",
                "possible",
                "unknown",
            ):
                raise ValueError("Finding requires text, certainty, evidence")
            if (
                not isinstance(finding["text"], str)
                or not finding["text"].strip()
                or len(finding["text"]) > 4000
            ):
                raise ValueError("Finding text required, <=4000")
            if not isinstance(finding["evidence"], list) or len(finding["evidence"]) > 30:
                raise ValueError("Finding evidence must be a list of up to 30 citations")
            if finding["certainty"] != "unknown" and not finding["evidence"]:
                raise ValueError("Confirmed/possible findings require citations")
            levels = []
            for ref in finding["evidence"]:
                if set(ref) - {"object_id", "revision", "claim_key"} or not {
                    "object_id",
                    "revision",
                }.issubset(ref):
                    raise ValueError("Citation requires object_id and revision")
                obj = store.get(ref["object_id"])
                if (
                    obj["kind"] not in ("card", "check", "link")
                    or obj["revision"] != ref["revision"]
                    or obj.get("status") in ("stale", "rejected", "superseded")
                    or pending(obj)
                ):
                    raise ValueError(
                        "Report citation must reference a current reviewed card/check/link revision"
                    )
                if obj["kind"] == "card" and obj.get("event", {}).get("claims"):
                    claims = [c for c in obj["event"]["claims"] if c["key"] == ref.get("claim_key")]
                    if len(claims) != 1:
                        raise ValueError("Cite an exact claim_key for a structured claim")
                    levels.append(claims[0]["level"])
                elif ref.get("claim_key"):
                    raise ValueError("Unknown claim_key")
            if section == "impacts" and finding["certainty"] == "confirmed" and "application" not in levels:
                raise ValueError(
                    "Confirmed impact needs application-level evidence; request/HTTP response alone is insufficient"
                )
    return content


def event_order(card):
    value = card.get("time_range", "unknown")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is not None:
            return (0, parsed.timestamp(), card["id"])
    except ValueError:
        pass
    return (1, 0, card["id"])


def chapters(store, meta, assessment, content, cards, links, checks, datasets, gaps, questions):
    from .integrity import environment_names

    names = environment_names(store)

    def env_of(c):
        value = c.get("event", {}).get("environment", "unknown")
        return names.get(value, value)

    live = [c for c in cards if c["status"] not in ("stale", "rejected", "superseded") and not pending(c)]
    labels = {o["id"]: f"E-{i:03d}" for i, o in enumerate(cards + links + checks, 1)}

    def cite(oid):
        return f"[{labels[oid]}](#evidence-{oid})"

    def findings(rows, recommendation=False):
        result = []
        for r in rows:
            refs = " ".join(
                cite(ref["object_id"])
                + " r"
                + str(ref["revision"])
                + ("#" + clean(ref["claim_key"]) if ref.get("claim_key") else "")
                for ref in r["evidence"]
            )
            certainty = {"confirmed": "已证实", "possible": "可能", "unknown": "无法判定"}[r["certainty"]]
            prefix = "建议" if recommendation else certainty
            result.append("- **" + prefix + "**：" + clean(r["text"]) + " " + refs)
        return result

    lines = [
        "## 1. 事件背景与调查范围",
        "",
        "用户反馈（待验证）：" + clean(meta.get("background") or "未提供背景，开展自主调查。"),
        "",
        clean(content["scope_note"]) if content else "范围以本调查登记的日志、已发布分区与下方证据附录为准。",
        "",
        f"当前可用数据集：{sum(d['status'] not in ('stale', 'rejected', 'superseded') for d in datasets)} 个。各分区行数与质量分别列于附录；不自动相加为唯一事件数量。",
        "时间沿用证据记录的时区与精度；无时区或缺失时间不得推定为 UTC。最早可见活动不等于真实攻击起点。",
        "",
        "## 2. 事件结论与影响评估",
        "",
    ]
    if content:
        lines += [
            "### 2.1 事件结论",
            "",
            *findings(content["conclusions"]),
            "",
            "### 2.2 影响评估",
            "",
            *findings(content["impacts"]),
        ]
    else:
        lines += [
            "历史/阶段摘要（自由文本，未提供结构化结论）：",
            clean(assessment),
            "",
            "确切影响：未提交可验证的结构化影响结论。",
        ]
    lines += [
        "",
        "## 3. 攻击时间线与攻击路径",
        "",
        "以下按环境分别列出事件；记录时间不明确时不强行排序，先后关系不自动构成因果。",
        "",
    ]
    environments = sorted({env_of(c) for c in live})
    for env in environments:
        lines += [
            "### 环境：" + clean(env),
            "",
            "| 记录时间（保留原时区） | 来源线索 | 资产 | 已观察事件 | 证据 |",
            "|---|---|---|---|---|",
        ]
        subset = [c for c in live if env_of(c) == env]
        for c in sorted(subset, key=event_order):
            e = c.get("event", {})
            sources = [x["address"] + "（" + x["field"] + "）" for x in card_sources(store, c)]
            lines.append(
                "| "
                + " | ".join(
                    [
                        clean(c.get("time_range", "unknown")),
                        clean("、".join(sources) or "未关联/未知"),
                        clean(e.get("asset", "unknown")),
                        clean(e.get("observed", c["statement"])),
                        cite(c["id"]),
                    ]
                )
                + " |"
            )
    if not live:
        lines += ["尚无当前有效事件，不能据此构造攻击路径。"]
    lines += ["", "### 已登记的事件关系", ""]
    for link in links:
        if link["status"] in ("stale", "rejected", "superseded") or pending(link):
            continue
        if not all(cid in {c["id"] for c in live} for cid in (link["from_card"], link["to_card"])):
            continue
        lines += [
            "- "
            + cite(link["from_card"])
            + " → "
            + cite(link["to_card"])
            + "："
            + clean(link["relation"])
            + "；"
            + ("推断关系" if link["inferred"] else "提交为直接观察的关系")
            + " "
            + cite(link["id"])
        ]
    lines += [
        "",
        "## 4. 攻击来源与具体行为",
        "",
        "来源记录不等于真实攻击者身份；共享出口、代理及转发头可信度需分别验证。",
        "",
    ]
    sources = aggregate(store)
    for source in sources:
        lines += [
            "### " + clean(source["address"]),
            f"- 来源字段：{clean(source['field'])}；匹配方式：{clean(source['match_mode'])}；可信度：{clean(source['attribution'])}",
        ]
        for card in source["cards"]:
            lines += [
                "- 事件："
                + cite(card["id"])
                + "；"
                + clean(card["environment"])
                + " / "
                + clean(card["asset"])
                + "；"
                + clean(card["time_range"])
                + ("" if card["current"] else "（历史/待复核，不作为当前事实）")
            ]
        for check in source["checks"]:
            lines += [
                "- 检查："
                + cite(check["id"])
                + "；"
                + clean(check["question"])
                + ("" if check["current"] else "（历史/过期/待复核）"),
                "  - 已查范围：" + clean(check["scope"]),
                "  - 结果："
                + clean(check["outcome"])
                + "；结论："
                + clean(check.get("conclusion") or "未单独记录，见检查和事件卡")
                + "；限制："
                + clean(check["limitations"]),
            ]
        lines += ["- 缺口：" + clean(gap) for gap in source["gaps"]]
    if not sources:
        lines += ["事件卡尚未关联来源；不代表不存在攻击来源。"]
    lines += [
        "",
        "## 5. 证据缺口与处置建议",
        "",
        *["- 证据缺口：" + clean(x) for x in gaps],
        *["- 待验证：" + clean(x) for x in questions],
    ]
    if content:
        lines += findings(content["recommendations"], recommendation=True)
    if not gaps and not questions:
        lines += ["未额外声明缺口；具体日志可见性限制仍见各排查记录。"]
    lines += ["", "## 附录：证据与调查记录", ""]
    for obj in cards + links + checks:
        lines += [
            '<a id="evidence-' + obj["id"] + '"></a>',
            f"- **{labels[obj['id']]}** → `{obj['id']}` r{obj['revision']}"
            + ("；原始引用：" + clean(json_refs(obj)) if obj["kind"] == "card" else ""),
        ]
    return lines, labels


def json_refs(obj):
    from .store import dumps

    return dumps(obj.get("evidence", []))
