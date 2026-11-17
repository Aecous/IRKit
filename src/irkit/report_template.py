"""Five fixed chapters with validated citations; semantics remain independently reviewed."""

import re
from typing import Literal, NotRequired, TypedDict

from .events import timestamp
from .integrity import pending


class Citation(TypedDict):
    object_id: str
    revision: int
    claim_key: NotRequired[str]


class Finding(TypedDict):
    text: str
    certainty: Literal["confirmed", "possible", "unknown"]
    evidence: list[Citation]


class AttackChain(TypedDict):
    title: str
    scope: str
    summary: Finding
    steps: list[Finding]
    connections: list[Finding]


class TimelineEntry(TypedDict):
    time: str
    source: str
    target: str
    activity: Finding


class SourceSummary(TypedDict):
    address: str
    role: str
    activity: Finding


class ReportInput(TypedDict):
    scope_note: str
    conclusions: list[Finding]
    impacts: list[Finding]
    recommendations: list[Finding]
    attack_chains: NotRequired[list[AttackChain]]
    post_exploitation: NotRequired[list[Finding]]
    timeline: NotRequired[list[TimelineEntry]]
    sources: NotRequired[list[SourceSummary]]


NARRATIVE_FIELDS = {"attack_chains", "post_exploitation", "timeline", "sources"}
BASE_FIELDS = {"scope_note", "conclusions", "impacts", "recommendations"}


def bounded_text(value, name, limit=4000):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f"{name}: nonempty text <= {limit} characters required")


def findings_in(content):
    """One traversal for citation validation, source checks, and evidence appendix selection."""
    for section in ("conclusions", "impacts", "recommendations", "post_exploitation"):
        for finding in content.get(section, []):
            yield section, finding
    for chain in content.get("attack_chains", []):
        yield "chain_summary", chain["summary"]
        for finding in chain["steps"]:
            yield "chain_step", finding
        for finding in chain["connections"]:
            yield "chain_connection", finding
    for row in content.get("timeline", []):
        yield "timeline", row["activity"]
    for row in content.get("sources", []):
        yield "source", row["activity"]


def validate(store, content, require_narrative=False):
    if (
        not isinstance(content, dict)
        or set(content) - BASE_FIELDS - NARRATIVE_FIELDS
        or not BASE_FIELDS <= set(content)
    ):
        raise ValueError("report_content requires scope_note, conclusions, impacts, recommendations")
    bounded_text(content["scope_note"], "scope_note", 6000)
    narrative = bool(NARRATIVE_FIELDS & set(content))
    if narrative and not NARRATIVE_FIELDS <= set(content):
        raise ValueError(
            "Narrative report requires attack_chains, post_exploitation, timeline and sources together"
        )
    for section in ("conclusions", "impacts", "recommendations", "post_exploitation"):
        rows = content.get(section, [])
        minimum = 0 if section == "post_exploitation" else 1
        if not isinstance(rows, list) or not minimum <= len(rows) <= 50:
            raise ValueError(f"{section}: supply {minimum}..50 findings")
    for name, maximum in (("attack_chains", 12), ("timeline", 40), ("sources", 30)):
        rows = content.get(name, [])
        if not isinstance(rows, list) or len(rows) > maximum:
            raise ValueError(f"{name}: list of at most {maximum} entries required")
    for chain in content.get("attack_chains", []):
        if not isinstance(chain, dict) or set(chain) != {"title", "scope", "summary", "steps", "connections"}:
            raise ValueError("Each attack chain needs title, scope, summary, steps and connections")
        bounded_text(chain["title"], "chain title", 160)
        bounded_text(chain["scope"], "chain scope", 600)
        for key in ("steps", "connections"):
            if not isinstance(chain[key], list) or not 1 <= len(chain[key]) <= 30:
                raise ValueError(f"chain {key}: 1..30 findings; describe an unknown connection explicitly")
    for name, fields in (("timeline", {"time", "source", "target"}), ("sources", {"address", "role"})):
        for row in content.get(name, []):
            if not isinstance(row, dict) or set(row) != fields | {"activity"}:
                raise ValueError(f"{name}: requires {sorted(fields)} and activity")
            for field in fields:
                bounded_text(row[field], f"{name}.{field}", 200)
            if not isinstance(row["activity"], dict):
                raise ValueError(f"{name}.activity requires a Finding")
            bounded_text(row["activity"].get("text"), f"{name}.activity", 700)
    for section, finding in findings_in(content):
        if (
            not isinstance(finding, dict)
            or set(finding) != {"text", "certainty", "evidence"}
            or finding["certainty"] not in {"confirmed", "possible", "unknown"}
        ):
            raise ValueError("Finding requires text, certainty, evidence")
        bounded_text(finding["text"], "Finding text")
        if not isinstance(finding["evidence"], list) or len(finding["evidence"]) > 30:
            raise ValueError("Finding evidence must be a list of up to 30 citations")
        if finding["certainty"] != "unknown" and not finding["evidence"]:
            raise ValueError("Confirmed/possible findings require citations")
        levels = []
        for ref in finding["evidence"]:
            if (
                not isinstance(ref, dict)
                or set(ref) - {"object_id", "revision", "claim_key"}
                or not {"object_id", "revision"} <= set(ref)
            ):
                raise ValueError("Citation requires object_id and revision")
            obj = store.get(ref["object_id"])
            if (
                obj["kind"] not in {"card", "check", "link"}
                or obj["revision"] != ref["revision"]
                or obj.get("status") in {"stale", "rejected", "superseded"}
                or pending(obj)
            ):
                raise ValueError("Report citation must reference a current reviewed card/check/link revision")
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
    if require_narrative and not narrative:
        raise ValueError(
            "Final report requires attack_chains, post_exploitation, timeline and sources; write the five-chapter narrative first"
        )
    return content


def event_order(card):
    event = card.get("event", {})
    timeline = event.get("timeline")
    # A node's position on the timeline prefers its explicit key_time annotation.
    stamp = event.get("key_time") or (timeline.get("start") if timeline is not None else None)
    if stamp is None:  # Legacy range strings only sort if the leading timestamp has an offset.
        match = re.match(
            r"^\s*(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2}))",
            card.get("time_range", ""),
        )
        stamp = match[1] if match else None
    if stamp:
        try:
            return (0, timestamp(stamp).timestamp(), card["id"])
        except ValueError:
            pass
    return (1, 0, card["id"])


def relation_display(link):
    kind = link.get("relation_type", "association")
    return {
        "sequence": ("→", "时序"),
        "causal": ("→", "因果"),
        "same_session": ("↔", "同会话"),
        "association": ("↔", "线索关联"),
    }[kind]


def prose(value):
    """Plain authored text, escaped for Markdown without turning paragraphs into HTML entities."""
    value = str(value).replace("\r\n", "\n").replace("\r", "\n")
    value = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return re.sub(r"([\\`*_{}\[\]#|])", r"\\\1", value)


def chapters(
    store,
    meta,
    assessment,
    content,
    cards,
    links,
    checks,
    datasets,
    gaps,
    questions,
    coverage=(),
    appendix_name="evidence.md",
):
    # Do not reconstruct a chain from card order or matching addresses. The author supplies
    # the narrative and explicit connections. Internal state remains in the workbench.
    labels = {}
    for _, finding in findings_in(content or {}):
        for ref in finding["evidence"]:
            labels.setdefault(ref["object_id"], f"E-{len(labels) + 1:03d}")

    def finding_text(finding, recommendation=False):
        refs = list(dict.fromkeys(ref["object_id"] for ref in finding["evidence"]))
        citations = " ".join(f"[{labels[oid]}]({appendix_name}#{labels[oid].lower()})" for oid in refs)
        prefix = {"confirmed": "", "possible": "**可能**：", "unknown": "**尚无法确认**："}[
            finding["certainty"]
        ]
        if recommendation:
            prefix = ""
        return prefix + prose(finding["text"]) + (" " + citations if citations else "")

    def paragraphs(rows, recommendation=False):
        out = []
        for row in rows:
            out += [finding_text(row, recommendation=recommendation), ""]
        return out

    lines = ["## 1. 事件概述", "", prose(content["scope_note"] if content else assessment), ""]
    if content:
        lines += paragraphs(content["conclusions"])
    lines += ["## 2. 攻击链路还原", ""]
    chains = (content or {}).get("attack_chains", [])
    for index, chain in enumerate(chains, 1):
        lines += [
            f"### 2.{index} {prose(chain['title'])}",
            "",
            prose(chain["scope"]),
            "",
            finding_text(chain["summary"]),
            "",
        ]
        for number, step in enumerate(chain["steps"], 1):
            # Each step is its own paragraph and includes the author's time, action and result.
            lines += [f"**步骤 {number}**", "", finding_text(step), ""]
        lines += ["**关联依据与边界**", "", *paragraphs(chain["connections"])]
    if not chains:
        lines += ["现有结果尚不足以组织出有证据支持的完整攻击链。不能据此排除其他攻击活动。", ""]
    lines += ["## 3. 后渗透操作与影响", "", "### 3.1 已观察到的后渗透操作", ""]
    post = (content or {}).get("post_exploitation", [])
    lines += paragraphs(post) if post else ["当前报告未确认可单独列出的后渗透操作。", ""]
    lines += ["### 3.2 影响评估", ""]
    lines += paragraphs(content["impacts"]) if content else ["当前证据不足以确认具体影响范围。", ""]
    lines += [
        "## 4. 攻击时间线与来源",
        "",
        "### 4.1 关键时间线",
        "",
        "时间以每项标明的时区与精度为准。最早可见记录不等于真实攻击起点。",
        "",
    ]
    timeline = (content or {}).get("timeline", [])
    if timeline:
        lines += ["| 时间 | 来源 | 目标 | 行为与结果 |", "| --- | --- | --- | --- |"]
        for row in timeline:
            cells = [prose(row[k]).replace("\n", " ") for k in ("time", "source", "target")]
            cells.append(finding_text(row["activity"]).replace("\n", " "))
            lines.append("| " + " | ".join(cells) + " |")
    else:
        lines += ["当前结果尚不足以列出可靠的关键时间线。"]
    lines += [
        "",
        "### 4.2 来源与相关地址",
        "",
        "来源地址、外联目标和跳板需分别理解；同一地址不能单独证明同一攻击者。",
        "",
    ]
    sources = (content or {}).get("sources", [])
    if sources:
        lines += ["| 地址 | 角色 | 关联行为与归因边界 |", "| --- | --- | --- |"]
        for row in sources:
            lines.append(
                "| "
                + " | ".join(
                    [
                        prose(row["address"]),
                        prose(row["role"]),
                        finding_text(row["activity"]).replace("\n", " "),
                    ]
                )
                + " |"
            )
    else:
        lines += ["现有结果未确定可可靠归因的攻击来源。"]
    lines += ["", "## 5. 调查局限与处置建议", "", "### 5.1 影响结论的证据局限", ""]
    lines += ["- " + prose(gap) for gap in gaps] or ["本次未额外列出局限，结论仍限定于上述可见数据。"]
    if questions:
        lines += ["", "需要进一步确认：", "", *["- " + prose(q) for q in questions]]
    lines += ["", "### 5.2 处置建议", ""]
    if content:
        lines += paragraphs(content["recommendations"], recommendation=True)
    else:
        lines += ["需结合已确认的行为和实际环境制定处置措施。", ""]
    lines += ["---", "", f"[证据明细附录]({appendix_name})", ""]
    return lines, labels
