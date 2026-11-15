from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import duckdb

from .evidence import raw_ref
from .execution import run_process
from .store import dumps, now, uid


def run_transform(store, source_ids, code, timeout=0):
    if type(timeout) is not int or timeout < 0:
        raise ValueError("Timeout must be a nonnegative integer; 0 means no deadline")
    if not source_ids or len(code.encode()) > 256_000:
        raise ValueError("Sources required; code limit is 256KB")
    sources = {sid: store.get(sid, "source") for sid in source_ids}
    rid = uid("run")
    directory = store.root / "runs" / rid
    directory.mkdir()
    (directory / "transform.py").write_text(code, encoding="utf-8")
    config = {
        "sources": {
            sid: {"path": str(store.path(s["path"])), "record_kind": s["record_kind"]}
            for sid, s in sources.items()
        }
    }
    (directory / "config.json").write_text(dumps(config))
    store.put(
        "run",
        {
            "operation": "transform",
            "status": "running",
            "started": now(),
            "sources": source_ids,
            "path": f"runs/{rid}",
            "code_sha256": hashlib.sha256(code.encode()).hexdigest(),
        },
        object_id=rid,
        dependencies=source_ids,
    )
    try:
        outcome = run_process(
            [
                sys.executable,
                "-I",
                Path(__file__).with_name("worker.py"),
                "transform",
                directory / "config.json",
            ],
            directory,
            timeout,
        )
        if outcome["status"] == "succeeded":
            # Runtime metrics are advisory; publisher independently validates every row/ref.
            metrics = directory / "metrics.json"
            if (
                metrics.is_symlink()
                or not metrics.is_file()
                or metrics.stat().st_nlink != 1
                or metrics.stat().st_size > 64000
            ):
                raise ValueError("Invalid metrics output")
            outcome["metrics"] = json.loads(metrics.read_text())
    except Exception as exc:
        outcome = {"status": "failed", "error": str(exc)}
    return store.update(rid, {**outcome, "finished": now()})


def publish_dataset(store, run_id, description, field_notes, quality, query_examples):
    run = store.get(run_id, "run")
    if run.get("operation") != "transform" or run["status"] != "succeeded":
        raise ValueError("Only a successful transform can be published")
    if not description.strip() or not field_notes or not quality.strip():
        raise ValueError("Description, field notes, and honest quality notes are required")
    output = store.path(f"{run['path']}/rows.jsonl")
    if (
        output.is_symlink()
        or not output.is_file()
        or output.stat().st_nlink != 1
    ):
        raise ValueError("Invalid transform output file")
    did = uid("ds")
    directory = store.root / "datasets" / did
    directory.mkdir()
    counts, fields, row_count = {}, set(), 0
    try:
        with output.open() as source, (directory / "rows.jsonl").open("w") as target:
            for line in source:
                if len(line.encode()) > 2 * 1024**2:
                    raise ValueError("Dataset row exceeds 2MB")
                row = json.loads(line)
                if not isinstance(row, dict) or not isinstance(row.get("_refs"), list) or not row["_refs"]:
                    raise ValueError("Every row needs a nonempty _refs list")
                for ref in row["_refs"]:
                    if ref.get("source_id") not in run["sources"]:
                        raise ValueError("Reference is outside approved run sources")
                    raw_ref(store, ref, counts=counts)
                row_count += 1
                if any(key.startswith("_") and key not in ("_row_id", "_refs") for key in row):
                    raise ValueError("Reserved field name")
                row["_row_id"] = row_count
                fields.update(row)
                target.write(dumps(row) + "\n")
        if not row_count:
            raise ValueError("Empty dataset; record an incomplete check instead of publishing")
        if len(fields) > 200:
            raise ValueError("Dataset exceeds 200 fields")
        dbpath = directory / "data.duckdb"
        con = duckdb.connect(str(dbpath))
        try:
            con.execute(
                "CREATE TABLE events AS SELECT * FROM read_json_auto(?, format='newline_delimited', "
                "union_by_name=true, sample_size=-1, maximum_object_size=4194304, "
                "timestampformat='__irkit_no_auto_timestamp__', dateformat='__irkit_no_auto_date__')",
                [str(directory / "rows.jsonl")],
            )
            schema = [{"name": r[0], "type": r[1]} for r in con.execute("DESCRIBE events").fetchall()]
        finally:
            con.close()
        for path in directory.iterdir():
            path.chmod(0o400)
        return store.put(
            "dataset",
            {
                "run_id": run_id,
                "path": f"datasets/{did}/data.duckdb",
                "description": description,
                "schema": schema,
                "field_notes": field_notes,
                "quality": quality,
                "query_examples": query_examples,
                "row_count": row_count,
                "sources": run["sources"],
                "source_record_counts": [
                    {"source_id": k[0], "encoding": k[1], "records": v} for k, v in counts.items()
                ],
                "status": "provisional",
            },
            object_id=did,
            dependencies=[run_id],
        )
    except BaseException:
        import shutil

        shutil.rmtree(directory)
        raise


def query_dataset(store, dataset_ids, sql, max_rows=1000, timeout=0):
    if not dataset_ids or not 1 <= max_rows <= 10000 or len(sql) > 40000:
        raise ValueError("Choose datasets, max_rows 1..10000, SQL <= 40000 chars")
    datasets = {did: store.get(did, "dataset") for did in dataset_ids}
    rid = uid("run")
    directory = store.root / "runs" / rid
    directory.mkdir()
    config = {
        "core_datasets": [
            did for did, ds in datasets.items() if ds.get("storage_layout") == "jsonl_batch_v1"
        ],
        "datasets": {did: str(store.path(ds["path"])) for did, ds in datasets.items()},
        "sql": sql,
        "max_rows": max_rows,
    }
    (directory / "config.json").write_text(dumps(config))
    store.put(
        "run",
        {
            "operation": "query",
            "status": "running",
            "started": now(),
            "datasets": dataset_ids,
            "sql": sql,
            "path": f"runs/{rid}",
            "scratch_database": f"runs/{rid}/analysis.duckdb",
        },
        object_id=rid,
        dependencies=dataset_ids,
    )
    try:
        outcome = run_process(
            [sys.executable, "-I", Path(__file__).with_name("worker.py"), "query", directory / "config.json"],
            directory,
            timeout,
        )
        if outcome["status"] == "succeeded":
            outcome.update(json.loads((directory / "result_meta.json").read_text()))
    except Exception as exc:
        outcome = {"status": "failed", "error": str(exc)}
    result = store.update(rid, {**outcome, "finished": now()})
    # Full result stays on disk; trim preview independently from saved-row truncation.
    if len(dumps(result.get("preview", []))) > 20000:
        result["preview"] = []
        result["preview_omitted"] = "Use read_query_result or narrower SELECT"
    return result


def read_query_result(store, query_id, offset=0, limit=20):
    run = store.get(query_id, "run")
    if run.get("operation") != "query" or run["status"] != "succeeded":
        raise ValueError("Not a successful query")
    if offset < 0 or not 1 <= limit <= 100:
        raise ValueError("Invalid result page")
    rows, size = [], 0
    with store.path(f"{run['path']}/results.jsonl").open() as stream:
        for index, line in enumerate(stream):
            if index < offset:
                continue
            if not rows and len(line) > 24000:
                raise ValueError(
                    f"Result row at offset {offset} exceeds display budget; SELECT narrower columns"
                )
            if len(rows) >= limit or size + len(line) > 24000:
                break
            rows.append(json.loads(line))
            size += len(line)
    return {
        "query_id": query_id,
        "offset": offset,
        "rows": rows,
        "saved_rows": run["saved_rows"],
        "query_truncated": run["truncated"],
        "next_offset": offset + len(rows) if offset + len(rows) < run["saved_rows"] else None,
    }


def dataset_row(store, dataset_id, row_id):
    ds = store.get(dataset_id, "dataset")
    if type(row_id) is not int or row_id < 1 or row_id > ds["row_count"]:
        raise ValueError("Invalid dataset row")
    con = duckdb.connect(str(store.path(ds["path"])), read_only=True)
    try:
        cursor = con.execute("SELECT * FROM events WHERE _row_id=?", [row_id])
        return dict(zip([c[0] for c in cursor.description], cursor.fetchone()))
    finally:
        con.close()
