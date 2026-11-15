"""Bounded bulk I/O jobs. These execute data operations, never model tasks."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

from .sandbox import run_isolated
from .store import Store, dumps, now, uid


def start_jsonl_ingest(store, source_ids, fields, required_fields=None):
    if not source_ids or not fields or len(fields) > 100:
        raise ValueError("Choose sources and 1..100 output-name -> JSON-key mappings")
    if len({name.casefold() for name in fields}) != len(fields):
        raise ValueError("Output column names must be unique ignoring case")
    for name, key in fields.items():
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", name) or name.casefold() in (
            "parse_status",
            "auth_fingerprint",
        ):
            raise ValueError(f"Invalid or reserved output column: {name}")
        if not isinstance(key, str) or len(key) > 200:
            raise ValueError("JSON keys must be strings <=200 chars")
    sources = [store.get(sid, "source") for sid in dict.fromkeys(source_ids)]
    if any(s["record_kind"] != "text" or not s.get("line_index") for s in sources):
        raise ValueError("Bulk JSONL currently requires indexed, uncompressed text sources")
    with store.transaction() as con:
        ensure_no_active_ingest(con)
        rid = uid("run")
        directory = store.root / "runs" / rid
        directory.mkdir()
        run = store.put(
            "run",
            {
                "operation": "ingest_jsonl",
                "status": "running",
                "started": now(),
                "sources": [s["id"] for s in sources],
                "fields": fields,
                "required_fields": ["authorization", "request_body"]
                if required_fields is None
                else required_fields,
                "path": f"runs/{rid}",
                "dataset_ids": [],
                "completed_sources": 0,
                "failed_sources": [],
                "current_source": None,
            },
            object_id=rid,
            dependencies=[source["id"] for source in sources],
            con=con,
        )
    return launch_driver(store, run)


def launch_driver(store, run):
    rid = run["id"]
    directory = store.path(run["path"])
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(directory),
        "LANG": "en_US.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    try:
        with (directory / "driver.log").open("ab") as log:
            process = subprocess.Popen(
                [sys.executable, "-m", "irkit.bulk", str(store.root), rid],
                cwd=directory,
                env=env,
                stdout=log,
                stderr=log,
                start_new_session=True,
            )
    except OSError:
        store.update(rid, {"status": "failed", "finished": now()})
        raise
    store.update(rid, {"driver_pid": process.pid})
    return {**run, "poll_tool": "ingest_status", "suggested_wait_seconds": 30}


def ensure_no_active_ingest(con, exclude=None):
    if con.execute(
        """SELECT 1 FROM objects WHERE kind='run' AND id != ?
           AND json_extract(data,'$.operation')='ingest_jsonl'
           AND json_extract(data,'$.status')='running'""",
        (exclude or "",),
    ).fetchone():
        raise ValueError("Another JSONL job is running")


def resume_jsonl_ingest(store, run_id):
    with store.transaction() as con:
        run = store.get(run_id, "run", con)
        if run.get("operation") != "ingest_jsonl" or run["status"] not in ("partial", "failed", "running"):
            raise ValueError("Resume requires a failed, partial or interrupted JSONL run")
        if run["status"] == "running":
            pid = run.get("driver_pid")
            if not pid:
                raise ValueError("Driver startup is in progress")
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                pass
            else:
                raise ValueError("Driver is still running")
        if run.get("field_incomplete_datasets") and not run.get("failed_sources"):
            raise ValueError("Create a new job with the missing required field mappings")
        ensure_no_active_ingest(con, exclude=run_id)
        run = store.update(
            run_id, {"status": "running", "driver_pid": None, "failed_sources": [], "finished": None}, con=con
        )
    return launch_driver(store, run)


def ingest_status(store, run_id, wait_seconds=0):
    if not 0 <= wait_seconds <= 30:
        raise ValueError("wait_seconds must be 0..30")
    run = store.get(run_id, "run")
    if run.get("operation") != "ingest_jsonl":
        raise ValueError("Not a bulk ingestion job")
    deadline = time.monotonic() + wait_seconds
    while run["status"] == "running" and time.monotonic() < deadline:
        time.sleep(min(2, max(0, deadline - time.monotonic())))
        run = store.get(run_id, "run")
    if sid := run.get("current_source"):
        progress = store.path(run["path"]) / sid / "progress.json"
        if progress.is_file():
            state = json.loads(progress.read_text())
            run["current_progress"] = {
                key: state[key] for key in ("committed_lines", "offset_bytes", "resumed_from_line")
            }
    return run


def drive(store, run_id):
    run = store.get(run_id, "run")
    published = {d["sources"][0]: d["id"] for d in store.all("dataset") if d.get("run_id") == run_id}
    datasets, failed = list(published.values()), []
    for sid in run["sources"]:
        if sid in published:
            continue
        source = store.get(sid, "source")
        directory = store.path(run["path"]) / sid
        directory.mkdir(exist_ok=True)
        store.update(run_id, {"current_source": sid, "heartbeat": now()})
        config = {
            "source": str(store.path(source["path"])),
            "source_id": sid,
            "expected_records": source["record_count_lf"],
            "fields": run["fields"],
            "required_fields": run.get("required_fields", ["authorization", "request_body"]),
            "source_sha256": source["sha256"],
        }
        (directory / "config.json").write_text(dumps(config))
        started = time.monotonic()
        try:
            outcome = (
                {"status": "succeeded"}
                if (directory / "metadata.json").is_file()
                else run_isolated(
                    [
                        sys.executable,
                        "-I",
                        Path(__file__).with_name("bulk_worker.py"),
                        str(directory / "config.json"),
                    ],
                    directory,
                    [store.path(source["path"])],
                    timeout=1800,
                    file_limit_mb=16384,
                )
            )
            if outcome["status"] != "succeeded":
                raise RuntimeError(dumps(outcome))
            meta = json.loads((directory / "metadata.json").read_text())
            marker = directory / "dataset_id.txt"
            if not marker.exists():
                marker.write_text(uid("ds"))
            did = marker.read_text()
            destination = store.root / "datasets" / did
            destination.mkdir(exist_ok=True)
            if not (destination / "data.duckdb").exists():
                os.link(directory / "data.duckdb", destination / "data.duckdb")
            (destination / "data.duckdb").chmod(0o400)
            store.put(
                "dataset",
                {
                    "run_id": run_id,
                    "path": f"datasets/{did}/data.duckdb",
                    "description": f"Full JSONL source {source['original_path']}",
                    "schema": meta["schema"],
                    "field_notes": run["fields"],
                    "quality": f"Full physical-line ingestion; {dumps(meta['parse_counts'])}; "
                    f"encoding_repaired_rows={meta.get('encoding_repaired_rows', 0)}. "
                    "Core fields have typed derivatives; complete projected token/body stored in request_details. "
                    "Invalid JSON rows retained with provenance. _encoding_status=byte_escaped marks invalid "
                    "UTF8 bytes represented as U+00xx; raw byte evidence is unchanged. "
                    "Use read_source(encoding='latin-1') to inspect such raw rows. Model interpretation provisional.",
                    "query_examples": [f"SELECT parse_status, count(*) FROM {did} GROUP BY 1"],
                    "row_count": meta["rows"],
                    "sources": [sid],
                    "source_record_counts": [
                        {"source_id": sid, "encoding": "utf-8", "records": meta["rows"]}
                    ],
                    "status": "provisional",
                    "storage_layout": "jsonl_batch_v1",
                    "field_coverage": meta["field_coverage"],
                    "observed_fields": meta["observed_fields"],
                    "omitted_fields": meta["omitted_fields"],
                    "missing_critical_fields": meta["missing_critical_fields"],
                    "resumed_from_line": meta["resumed_from_line"],
                    "peak_rss_bytes": meta["peak_rss_bytes"],
                    "parse_counts": meta["parse_counts"],
                    "encoding_repaired_rows": meta.get("encoding_repaired_rows", 0),
                    "ingest_seconds": round(time.monotonic() - started, 3),
                    "storage_bytes": (destination / "data.duckdb").stat().st_size,
                },
                object_id=did,
                dependencies=[run_id, sid],
            )
            (directory / "data.duckdb").unlink(missing_ok=True)
            datasets.append(did)
        except Exception as exc:
            failed.append({"source_id": sid, "error": str(exc)[-5000:]})
        store.update(
            run_id,
            {
                "dataset_ids": datasets,
                "failed_sources": failed,
                "completed_sources": len(datasets) + len(failed),
                "heartbeat": now(),
            },
        )
    incomplete = [did for did in datasets if store.get(did).get("missing_critical_fields")]
    store.update(
        run_id,
        {
            "field_incomplete_datasets": incomplete,
            "status": "partial"
            if datasets and (failed or incomplete)
            else "failed"
            if failed
            else "succeeded",
            "current_source": None,
            "finished": now(),
        },
    )


if __name__ == "__main__":
    store = Store(sys.argv[1])
    run_id = sys.argv[2]
    try:
        drive(store, run_id)
    except Exception as error:
        store.update(run_id, {"status": "failed", "driver_error": str(error), "finished": now()})
        raise
