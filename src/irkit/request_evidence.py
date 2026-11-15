"""Bounded offline inspection of request bodies from original indexed JSONL rows."""

from __future__ import annotations

import hashlib
import json
import re
from contextlib import closing

from .evidence import source_records

MAX_DECODED_BYTES = 128 * 1024
MAX_REFS = 12

_IDENTIFIER = r"(?:[A-Za-z_][\w]*|`[A-Za-z_][\w]*`)"
_SQL_START = re.compile(
    rf"^(?P<verb>INSERT(?:\s+IGNORE)?\s+INTO|UPDATE|DELETE\s+FROM)\s+"
    rf"(?P<table>{_IDENTIFIER}(?:\s*\.\s*{_IDENTIFIER})?)(?=\s|\(|$)",
    re.I,
)
_SQL_TOKEN = re.compile(r"'(?:''|\\.|[^'\\])*'|`[^`]*`|/\*.*?\*/|--[^\r\n]*|#[^\r\n]*|.", re.S)
_ACCOUNT = re.compile(r"[A-Za-z0-9_.@-]{1,80}")
_ROUTE_KEY = re.compile(r"zuul\.routes\.([\w-]{1,80})\.(path|url|serviceId|stripPrefix)", re.I)


def safe_account(value):
    return value if isinstance(value, str) and _ACCOUNT.fullmatch(value) else None


def account_literal(value):
    value = value.strip()
    return safe_account(value[1:-1]) if value.startswith("'") and value.endswith("'") else None


def first_values_tuple(text):
    """Split the first SQL VALUES tuple while respecting quoted strings and nested calls."""
    values, start, depth = [], 0, 0
    for match in _SQL_TOKEN.finditer(text):
        token = match[0]
        if token == "(":
            depth += 1
        elif token == ")":
            if not depth:
                return [*values, text[start : match.start()]]
            depth -= 1
        elif token == "," and not depth:
            values.append(text[start : match.start()])
            start = match.end()
    return []


def sql_summary(sql):
    cleaned = "".join(
        " " if m[0].startswith(("/*", "--", "#")) else m[0] for m in _SQL_TOKEN.finditer(sql)
    ).strip()
    match = _SQL_START.match(cleaned)
    if not match:
        leading = re.match(r"\w+", cleaned)
        keyword = leading[0].upper() if leading else ""
        return {"operation": keyword if keyword in {"SELECT", "SHOW", "CREATE", "ALTER", "DROP"} else "other"}
    operation = match["verb"].split()[0].upper()
    table = re.sub(r"[\s`]", "", match["table"])
    summary = {"operation": operation, "table": table[:128]}
    account = None
    if operation == "INSERT":
        columns = re.match(r"\s*\(([^()]*)\)\s*VALUES\s*\(", cleaned[match.end() :], re.I)
        if columns:
            names = [name.strip().strip("`").lower() for name in columns[1].split(",")]
            values = first_values_tuple(cleaned[match.end() + columns.end() :])
            if len(values) == len(names):
                for key in ("username", "user_name"):
                    if key in names:
                        account = account_literal(values[names.index(key)])
                        break
    elif operation in {"UPDATE", "DELETE"}:
        predicate = re.search(
            r"\bWHERE\s+`?(?:username|user_name)`?\s*=\s*('(?:''|\\.|[^'\\])*')", cleaned, re.I
        )
        if predicate:
            account = account_literal(predicate[1])
    if account:
        summary["account_candidate"] = account
    return summary


def inspect_request(store, source_id, line, body_field="request_body", chain=None):
    if type(line) is not int or line < 1:
        raise ValueError("Use a positive physical line number")
    source = store.get(source_id, "source")
    if source["record_kind"] != "text" or not source.get("line_index"):
        raise ValueError("Request inspection requires indexed JSONL text")
    # Read the original row without applying the display limit or the UTF-8 ingest repairs.
    with closing(source_records(store, source_id, "latin-1", start=line)) as records:
        record = next(records, None)
    if record is None:
        raise ValueError("Requested physical line does not exist")
    result = {"_refs": [{"source_id": source_id, "start": line, "end": line}]}
    try:
        raw = json.loads(record[1])
    except ValueError:
        return {**result, "decode_status": "invalid_log_json"}
    if not isinstance(raw, dict):
        return {**result, "decode_status": "invalid_log_json"}
    result["event"] = {
        name: raw[name][:240] if isinstance(raw[name], str) else raw[name]
        for name in ("@timestamp", "domain", "host", "request_method", "status", "size")
        if name in raw and isinstance(raw[name], (str, int, float))
    }
    # URI values can contain session tokens. Return no URL or query-string literal.
    auth = raw.get("authorization")
    if isinstance(auth, str) and auth and auth.isascii():
        result["auth_fingerprint"] = hashlib.sha256(auth.encode("ascii")).hexdigest()
    from .decoding import decode_original

    decoded = decode_original(record[1], body_field, chain)
    result.update({k: v for k, v in decoded.items() if k != "text"})
    result["raw_sha256"] = hashlib.sha256(record[1].encode("latin-1")).hexdigest()
    if decoded["decode_status"] != "decoded":
        return result
    if decoded.get("format") != "json":
        return result
    obj = json.loads(decoded["text"])
    if not isinstance(obj, dict):
        return result
    sql = obj.get("sql")
    if isinstance(sql, str):
        result["sql"] = sql_summary(sql)
    for name in ("username", "userName", "user_name"):
        if account := safe_account(obj.get(name)):
            result["account_candidate"] = account
            break
    key = obj.get("name")
    if isinstance(key, str) and "value" in obj and (route := _ROUTE_KEY.fullmatch(key)):
        result["route_config_submission"] = {"route_id": route[1], "property": route[2]}
    return result


def inspect_requests(store, refs, task_id=None, body_field="request_body", chain=None):
    if not 1 <= len(refs) <= MAX_REFS:
        raise ValueError(f"Choose 1..{MAX_REFS} exact raw row references")
    for ref in refs:
        if (
            set(ref) != {"source_id", "start", "end"}
            or type(ref["start"]) is not int
            or type(ref["end"]) is not int
            or ref["start"] != ref["end"]
        ):
            raise ValueError("Each reference must be a single physical row: source_id, start=end")
    if task_id:
        task = store.get(task_id, "task")
        if task["status"] != "running":
            raise ValueError("Inspection needs a running task")
        allowed_sources = set()
        for oid in task["input_ids"]:
            obj = store.get(oid)
            if obj["kind"] == "dataset":
                allowed_sources.update(obj["sources"])
            elif obj["kind"] == "source":
                allowed_sources.add(oid)
        if not {r["source_id"] for r in refs}.issubset(allowed_sources):
            raise ValueError("Inspection sources must belong to task inputs")
    results = []
    for ref in refs:
        try:
            results.append(inspect_request(store, ref["source_id"], ref["start"], body_field, chain))
        except (ValueError, OSError) as exc:
            results.append({"_refs": [ref], "decode_status": "source_read_failed", "error": str(exc)})
    from collections import Counter

    coverage = dict(Counter(r["decode_status"] for r in results))
    run = store.put(
        "run",
        {
            "operation": "body_inspection",
            "status": "succeeded",
            "task_id": task_id,
            "body_field": body_field,
            "chain": chain,
            "selection": "exact_refs",
            "refs": refs,
            "candidate_count": len(refs),
            "processed_count": len(results),
            "coverage": coverage,
            "records": results,
            "body_presence": dict(Counter(r.get("body_state", "unknown") for r in results)),
        },
        dependencies={r["source_id"] for r in refs},
    )
    return {
        "run_id": run["id"],
        "records": results,
        "coverage": coverage,
        "scope_note": "Exact referenced rows only; not dataset-wide absence or full decode coverage",
    }
