"""Resumable, case-local decoding with raw provenance and explicit coverage."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import sqlite3
import zlib
from contextlib import closing
from urllib.parse import parse_qs, unquote_to_bytes

import duckdb

from .evidence import source_records
from .request_evidence import sql_summary
from .store import dumps, now, uid

VERSION = 2
MAX_BYTES = 131072
STEPS = {"gzip", "base64", "hex", "url"}


def transform(data, step):
    if step == "gzip":
        decoder = zlib.decompressobj(31)
        result = decoder.decompress(data, MAX_BYTES + 1)
        if len(result) > MAX_BYTES or decoder.unconsumed_tail:
            raise ValueError("expanded_size_limit")
        if not decoder.eof or decoder.unused_data:
            raise ValueError("incomplete_or_multiple_gzip")
        return result
    if step == "base64":
        clean = re.sub(rb"\s", b"", data)
        return base64.b64decode(clean + b"=" * (-len(clean) % 4), altchars=b"-_", validate=True)
    if step == "hex":
        return bytes.fromhex(data.decode("ascii"))
    if step == "url":
        return unquote_to_bytes(data.decode("ascii"))
    raise ValueError("unknown_step")


def terminal(data):
    text = data.decode("utf-8")
    try:
        value = json.loads(text)
        if isinstance(value, (dict, list)):
            return text, value, "json"
    except ValueError:
        pass
    # Base64 padding is not a form assignment (e.g. eyJ...==).
    padded_base64 = re.fullmatch(r"[A-Za-z0-9+/_-]+={1,2}", text)
    if not padded_base64 and re.search(r"(^|&)[A-Za-z_][\w.-]*=", text):
        return text, {k: v[0] for k, v in parse_qs(text).items()}, "form"
    return text, None, "text"


def decode(data, chain=None):
    """Auto detection accepts structured terminals; explicit chains may end in text."""
    if not data:
        return {"decode_status": "absent", "chain": [], "semantic_status": "unclassified"}
    if len(data) > MAX_BYTES:
        return {"decode_status": "size_limit", "chain": [], "semantic_status": "unclassified"}
    if chain is not None:
        if len(chain) > 6 or any(s not in STEPS for s in chain):
            raise ValueError("Use up to six gzip/base64/hex/url steps")
        try:
            value = data
            for step in chain:
                value = transform(value, step)
                if len(value) > MAX_BYTES:
                    raise ValueError("expanded_size_limit")
            text, obj, kind = terminal(value)
            candidates = [(chain, text, obj, kind)]
        except (ValueError, UnicodeError, zlib.error, binascii.Error) as exc:
            return {
                "decode_status": "failed",
                "chain": chain,
                "error": str(exc),
                "semantic_status": "unclassified",
            }
    else:
        candidates, queue, seen, failures = [], [(data, [])], set(), []
        while queue:
            value, used = queue.pop(0)
            digest = hashlib.sha256(value).digest()
            if digest in seen or len(value) > MAX_BYTES:
                continue
            seen.add(digest)
            try:
                text, obj, kind = terminal(value)
                if obj is not None:
                    candidates.append((used, text, obj, kind))
                    continue
            except (ValueError, UnicodeError):
                pass
            if len(used) >= 6:
                continue
            steps = []
            if value.startswith(b"\x1f\x8b"):
                steps.append("gzip")
            if len(value) >= 8 and re.fullmatch(rb"[A-Za-z0-9_+/=\s-]+", value):
                steps.append("base64")
            if len(value) >= 4 and len(value) % 2 == 0 and re.fullmatch(rb"[0-9a-fA-F]+", value):
                steps.append("hex")
            if re.search(rb"%[0-9a-fA-F]{2}", value):
                steps.append("url")
            for step in steps:
                try:
                    result = transform(value, step)
                    queue.append((result, [*used, step]))
                except (ValueError, UnicodeError, zlib.error, binascii.Error) as exc:
                    failures.append({"chain": [*used, step], "error": str(exc)[:200]})
        if not candidates:
            return {
                "decode_status": "size_limit"
                if any(f["error"] == "expanded_size_limit" for f in failures)
                else "failed"
                if data.startswith(b"\x1f\x8b") and failures
                else "unresolved",
                "chain": [],
                "attempts": failures,
                "semantic_status": "unclassified",
                "reason": "No validated structured result; use an explicit chain or custom transform",
            }
    distinct = {c[1]: c for c in candidates}
    if len(distinct) > 1:
        return {
            "decode_status": "ambiguous",
            "candidates": [c[0] for c in candidates],
            "semantic_status": "unclassified",
        }
    chain, text, obj, kind = next(iter(distinct.values()))
    result = {
        "decode_status": "decoded",
        "chain": chain,
        "text": text,
        "format": kind,
        "semantic_status": "unclassified",
        "output_sha256": hashlib.sha256(text.encode()).hexdigest(),
    }
    if isinstance(obj, dict):
        if isinstance(obj.get("sql"), str):
            result["sql"] = sql_summary(obj["sql"])
            result["semantic_status"] = (
                "classified" if result["sql"]["operation"] != "other" else "unclassified"
            )
        if isinstance(obj.get("name"), str) and "value" in obj:
            result["config_key"] = obj["name"]
            result["semantic_status"] = "classified"
        for key in ("username", "user_name", "userName"):
            if isinstance(obj.get(key), str):
                result["account"] = obj[key]
                result["semantic_status"] = "classified"
                break
    return result


def decode_original(raw, body_field="request_body", chain=None):
    """Shared raw-byte path for inspection and bulk decoding; absence is not a read failure."""
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("Expected a JSON object")
    if body_field not in obj or obj[body_field] is None or obj[body_field] == "":
        state = "missing" if body_field not in obj else "null" if obj[body_field] is None else "empty"
        return {**decode(b""), "body_state": state, "body_field": body_field}
    body = obj[body_field]
    if not isinstance(body, str):
        # Structured JSON bodies are already decoded, not absent.
        data = json.dumps(body, ensure_ascii=False).encode()
    else:
        try:
            body = json.loads(raw.encode("latin-1").decode("utf-8"))[body_field]
        except (ValueError, UnicodeError):
            pass
        data = body.encode("latin-1") if body.startswith("\x1f\x8b") else body.encode("utf-8")
    return {**decode(data, chain), "body_state": "present", "body_field": body_field}


def start_decode(store, dataset_ids, filters, chain=None, task_id=None, body_field="request_body"):
    allowed = {
        "host",
        "domain",
        "request_path",
        "request_method",
        "time_from",
        "time_to",
        "source_ip_candidate",
    }
    if not dataset_ids or not filters or set(filters) - allowed:
        raise ValueError(
            "Provide datasets and exact filters: host/domain/request_path/request_method/time_from/time_to"
        )
    if chain is not None and (len(chain) > 6 or any(s not in STEPS for s in chain)):
        raise ValueError("Invalid chain")
    if not isinstance(body_field, str) or not body_field.strip():
        raise ValueError("Specify the original JSON body field")
    datasets = [store.get(did, "dataset") for did in dict.fromkeys(dataset_ids)]
    if any(d["status"] in ("stale", "superseded", "rejected") for d in datasets):
        raise ValueError("Use current datasets")
    if task_id:
        task = store.get(task_id, "task")
        if task["status"] != "running" or not set(dataset_ids).issubset(task["input_ids"]):
            raise ValueError("Use a running task with these datasets as inputs")
    rid = uid("run")
    directory = store.root / "runs" / rid
    directory.mkdir()
    store.put(
        "run",
        {
            "operation": "decode",
            "status": "running",
            "path": f"runs/{rid}",
            "datasets": [d["id"] for d in datasets],
            "filters": filters,
            "chain": chain,
            "body_field": body_field,
            "decoder_version": VERSION,
            "task_id": task_id,
            "started": now(),
            "phase": "selecting",
        },
        object_id=rid,
        dependencies=dataset_ids,
    )
    try:
        with closing(sqlite3.connect(directory / "decoded.sqlite")) as output:
            output.execute(
                "CREATE TABLE records (seq INTEGER PRIMARY KEY, dataset_id TEXT, source_id TEXT, line INTEGER, result TEXT, UNIQUE(source_id,line))"
            )
            output.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY,value TEXT)")
            for ds in datasets:
                clauses, params = [], []
                for key, value in filters.items():
                    column, op = {
                        "time_from": ("event_time_utc", ">="),
                        "time_to": ("event_time_utc", "<"),
                    }.get(key, (key, "="))
                    clauses.append(f'"{column}" {op} ?')
                    params.append(value)
                with closing(
                    duckdb.connect(
                        str(store.path(ds["path"])),
                        read_only=True,
                        config={"threads": 1, "memory_limit": "512MB"},
                    )
                ) as con:
                    cursor = con.execute("SELECT _refs FROM events WHERE " + " AND ".join(clauses), params)
                    while rows := cursor.fetchmany(2000):
                        for (refs,) in rows:
                            if len(refs) != 1 or refs[0]["start"] != refs[0]["end"]:
                                raise ValueError(
                                    "Body decoding requires single physical JSONL row references"
                                )
                            ref = refs[0]
                            if ref["source_id"] not in ds["sources"]:
                                raise ValueError("Invalid source mapping")
                            output.execute(
                                "INSERT OR IGNORE INTO records(dataset_id,source_id,line) VALUES (?,?,?)",
                                (ds["id"], ref["source_id"], ref["start"]),
                            )
                        output.commit()
            count = output.execute("SELECT count(*) FROM records").fetchone()[0]
            output.execute("INSERT INTO metadata VALUES ('selection_complete','true')")
            output.commit()
        return store.update(rid, {"phase": "decoding", "candidate_count": count, "processed_count": 0})
    except Exception as exc:
        store.update(rid, {"status": "failed", "error": str(exc), "phase": "selection_failed"})
        raise


def decoded_overview(db):
    """Describe every processed record, independently of the current result page/filter."""
    operations = db.execute(
        "SELECT json_extract(result,'$.sql.operation'),count(*),min(seq) FROM records "
        "WHERE result IS NOT NULL AND json_extract(result,'$.sql.operation') IS NOT NULL GROUP BY 1"
    ).fetchall()
    anchors = {}
    for operation, _, seq in operations:
        did, sid, line = db.execute(
            "SELECT dataset_id,source_id,line FROM records WHERE seq=?", (seq,)
        ).fetchone()
        anchors[operation] = {"dataset_id": did, "source_id": sid, "line": line}
    return {
        "scope": "entire decode run, all processed records; not limited by page/filter",
        "processed_count": db.execute("SELECT count(*) FROM records WHERE result IS NOT NULL").fetchone()[0],
        "sql_operations": {operation: count for operation, count, _ in operations},
        "operation_sample_refs": anchors,
        "formats": dict(
            db.execute(
                "SELECT coalesce(json_extract(result,'$.format'),'unrecognized'),count(*) FROM records "
                "WHERE result IS NOT NULL GROUP BY 1"
            )
        ),
        "semantic_status": dict(
            db.execute(
                "SELECT coalesce(json_extract(result,'$.semantic_status'),'unclassified'),count(*) FROM records "
                "WHERE result IS NOT NULL GROUP BY 1"
            )
        ),
    }


def decode_batch(store, run_id, batch_size=1000):
    run = store.get(run_id, "run")
    if run.get("operation") != "decode" or not 1 <= batch_size <= 2000:
        raise ValueError("Use a decode run and batch_size 1..2000")
    if run["decoder_version"] != VERSION:
        raise ValueError("Decoder version changed; create a new run")
    if any(store.get(d, "dataset")["status"] in ("superseded", "stale", "rejected") for d in run["datasets"]):
        raise ValueError("Input dataset changed")
    with closing(sqlite3.connect(store.path(run["path"]) / "decoded.sqlite", timeout=60)) as db:
        db.execute("BEGIN IMMEDIATE")
        if not db.execute("SELECT 1 FROM metadata WHERE key='selection_complete'").fetchone():
            raise ValueError("Selection incomplete; create a new run")
        rows = db.execute(
            "SELECT seq,source_id,line FROM records WHERE result IS NULL ORDER BY source_id,line LIMIT ?",
            (batch_size,),
        ).fetchall()
        for seq, sid, line in rows:
            try:
                with closing(source_records(store, sid, "latin-1", start=line)) as records:
                    ordinal, raw = next(records)
                if ordinal != line:
                    raise ValueError("Missing original row")
                result = decode_original(raw, run.get("body_field", "request_body"), run["chain"])
                result["raw_sha256"] = hashlib.sha256(raw.encode("latin-1")).hexdigest()
            except (ValueError, UnicodeError, OSError, StopIteration) as exc:
                result = {
                    "decode_status": "source_error",
                    "semantic_status": "unclassified",
                    "error": str(exc),
                }
            db.execute("UPDATE records SET result=? WHERE seq=?", (dumps(result), seq))
        db.commit()
        coverage = dict(
            db.execute(
                "SELECT json_extract(result,'$.decode_status'),count(*) FROM records WHERE result IS NOT NULL GROUP BY 1"
            )
        )
        classified = db.execute(
            "SELECT count(*) FROM records WHERE json_extract(result,'$.semantic_status')='classified'"
        ).fetchone()[0]
        body_presence = dict(
            db.execute(
                "SELECT coalesce(json_extract(result,'$.body_state'),'unknown'),count(*) "
                "FROM records WHERE result IS NOT NULL GROUP BY 1"
            )
        )
        total = db.execute("SELECT count(*) FROM records").fetchone()[0]
        processed = sum(coverage.values())
        return store.update(
            run_id,
            {
                "status": "succeeded" if processed == total else "running",
                "phase": "complete" if processed == total else "decoding",
                "coverage": coverage,
                "body_presence": body_presence,
                "candidate_count": total,
                "processed_count": processed,
                "classified_count": classified,
                "overview": decoded_overview(db),
                "updated_at": now(),
            },
        )


def read_decoded(store, run_id, offset=0, limit=20, operation=None, contains=None, include_text=False):
    run = store.get(run_id, "run")
    if run.get("operation") != "decode" or offset < 0 or not 1 <= limit <= 100:
        raise ValueError("Use decode run, offset >= 0, limit 1..100")
    clauses, params = ["result IS NOT NULL"], []
    if operation:
        clauses.append("json_extract(result,'$.sql.operation')=?")
        params.append(operation.upper())
    if contains:
        clauses.append("instr(lower(json_extract(result,'$.text')),lower(?)) > 0")
        params.append(contains)
    with closing(sqlite3.connect(store.path(run["path"]) / "decoded.sqlite")) as db:
        overview = decoded_overview(db)
        matching_total = db.execute(
            "SELECT count(*) FROM records WHERE " + " AND ".join(clauses), params
        ).fetchone()[0]
        rows = db.execute(
            "SELECT dataset_id,source_id,line,result FROM records WHERE "
            + " AND ".join(clauses)
            + " ORDER BY source_id,line LIMIT ? OFFSET ?",
            [*params, limit, offset],
        ).fetchall()
    result, size = [], 0
    for did, sid, line, value in rows:
        obj = json.loads(value)
        if not include_text:
            obj.pop("text", None)
        elif len(obj.get("text", "")) > 12000:
            obj["text"] = obj["text"][:12000]
            obj["text_truncated"] = True
        obj.update(dataset_id=did, source_id=sid, line=line)
        if result and size + len(dumps(obj)) > 24000:
            break
        result.append(obj)
        size += len(dumps(obj))
    return {
        "records": result,
        "next_offset": offset + len(result) if len(rows) == limit or len(result) < len(rows) else None,
        "coverage": run.get("coverage", {}),
        "status": run["status"],
        "overview": overview,
        "matching_total": matching_total,
    }
