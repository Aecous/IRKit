"""Sandboxed, resumable JSONL ingestion with physical-line provenance."""

import codecs
import fcntl
import hashlib
import json
import os
import resource
import sys
from pathlib import Path

import duckdb

BATCH_BYTES = 32 * 1024**2
BATCH_ROWS = 50000
MAX_LINE = 2 * 1024**2


def literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def identifier(value):
    return '"' + value.replace('"', '""') + '"'


def escape_bytes(error):
    return "".join(f"\\u00{byte:02x}" for byte in error.object[error.start : error.end]), error.end


def save_json(path, data):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False))
    temporary.replace(path)


def stage_batch(source, line_number):
    start = source.tell()
    with Path("batch.tsv").open("wb") as target:
        for _ in range(BATCH_ROWS):
            raw = source.readline(MAX_LINE + 1)
            if not raw:
                break
            line_number += 1
            state = "utf8"
            if len(raw) > MAX_LINE:
                while raw and not raw.endswith(b"\n"):
                    raw = source.readline(MAX_LINE + 1)
                raw = b""
                state = "oversized"
            else:
                raw = raw.removesuffix(b"\n").removesuffix(b"\r")
                try:
                    raw.decode("utf-8")
                except UnicodeDecodeError:
                    raw = raw.decode("utf-8", errors="irkit_json_bytes").encode("utf-8")
                    state = "byte_escaped"
                if b"\x02" in raw or b"\x00" in raw or b"\r" in raw:
                    raw = (
                        raw.replace(b"\x02", b"\\u0002")
                        .replace(b"\x00", b"\\u0000")
                        .replace(b"\r", b"\\u000d")
                    )
                    state = "byte_escaped"
            target.write(f"{line_number}\x02{state}\x02".encode() + raw + b"\n")
            if source.tell() - start >= BATCH_BYTES:
                break
    return line_number, source.tell()


def layout(fields):
    paths = [literal("/" + key.replace("~", "~0").replace("/", "~1")) for key in fields.values()]
    core, details, extra = {}, {}, {}
    for index, (name, key) in enumerate(fields.items(), 1):
        value = f"vals[{index}]"
        if key.casefold() in ("authorization", "request_body"):
            details[name] = value
            if key.casefold() == "authorization":
                details.setdefault("auth_fingerprint", f"sha256(nullif({value}, ''))")
        else:
            core[name] = value
        if key in ("status", "size", "responsetime"):
            kind = "INTEGER" if key == "status" else "BIGINT" if key == "size" else "DOUBLE"
            core[name] = f"try_cast({value} AS {kind})"
            extra[f"{name}_raw"] = value
        if key == "@timestamp":
            extra["event_time_utc"] = (
                f"CASE WHEN regexp_matches({value}, '(Z|[+-][0-9]{{2}}:?[0-9]{{2}})$') "
                f"THEN make_timestamp(epoch_us(try_cast({value} AS TIMESTAMPTZ))) END"
            )
        if key == "client_forward":
            extra["source_ip_candidate"] = f"nullif(trim(split_part({value}, ',', 1)), '')"
            extra["source_ip_basis"] = f"CASE WHEN {value} <> '' THEN 'unverified_forwarded_first_hop' END"
        if key == "request_uri":
            extra["request_path"] = f"split_part({value}, '?', 1)"
            extra["query_raw"] = (
                f"CASE WHEN strpos({value}, '?') > 0 THEN substr({value}, strpos({value}, '?')+1) END"
            )
    for name, expression in extra.items():
        if name not in fields:
            core[name] = expression
    projection = ", ".join(f"{expr} AS {identifier(name)}" for name, expr in (core | details).items())
    return ",".join(paths), projection, list(core), list(details)


def ingest(config):
    con = duckdb.connect(
        "data.duckdb",
        config={
            "threads": "2",
            "memory_limit": "1536MB",
            "temp_directory": "spill",
            "max_temp_directory_size": "2GB",
            "preserve_insertion_order": "true",
            "autoload_known_extensions": "false",
            "autoinstall_known_extensions": "false",
        },
    )
    signature = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
    con.execute(
        "CREATE TABLE IF NOT EXISTS ingest_checkpoint (signature VARCHAR, line BIGINT, offset_bytes BIGINT, keys VARCHAR[])"
    )
    checkpoint = con.execute("SELECT signature,line,offset_bytes,keys FROM ingest_checkpoint").fetchone()
    line_number, offset, observed = 0, 0, set()
    if checkpoint:
        if checkpoint[0] != signature:
            raise ValueError("Resume configuration differs from the committed checkpoint")
        line_number, offset, keys = checkpoint[1:]
        observed.update(keys)
    resumed_from = line_number
    paths, projection, core, details = layout(config["fields"])
    with Path(config["source"]).open("rb") as source:
        source.seek(offset)
        while True:
            next_line, next_offset = stage_batch(source, line_number)
            if next_line == line_number:
                break
            con.execute("""CREATE OR REPLACE TEMP TABLE batch AS
                SELECT _row_id, _encoding_status, raw, try_cast(raw AS JSON) j
                FROM read_csv('batch.tsv', header=false, auto_detect=false,
                  columns={'_row_id':'BIGINT','_encoding_status':'VARCHAR','raw':'VARCHAR'},
                  delim='\x02', quote='', escape='', parallel=false, new_line='\\n',
                  maximum_line_size=16777216, buffer_size=67108864)""")
            count, first, last = con.execute(
                "SELECT count(*),min(_row_id),max(_row_id) FROM batch"
            ).fetchone()
            if (count, first, last) != (next_line - line_number, line_number + 1, next_line):
                raise ValueError("Batch physical-line coverage mismatch")
            observed.update(
                row[0]
                for row in con.execute(
                    "SELECT DISTINCT unnest(keys) FROM (SELECT DISTINCT json_keys(j) keys FROM batch)"
                ).fetchall()
            )
            con.execute(f"""CREATE OR REPLACE TEMP TABLE projected AS
                SELECT _row_id, _encoding_status,
                CASE WHEN _encoding_status='oversized' THEN 'oversized'
                     WHEN raw IS NULL OR trim(raw)='' THEN 'empty' WHEN j IS NULL THEN 'invalid_json'
                     WHEN json_type(j)<>'OBJECT' THEN 'not_object' ELSE 'ok' END AS parse_status,
                {projection}
                FROM (SELECT *, json_extract_string(j,[{paths}]) vals FROM batch)""")
            core_columns = ", ".join(map(identifier, ["_row_id", "_encoding_status", "parse_status", *core]))
            detail_columns = ", ".join(map(identifier, ["_row_id", *details]))
            con.execute("BEGIN")
            con.execute(
                f"CREATE TABLE IF NOT EXISTS core_records AS SELECT {core_columns} FROM projected LIMIT 0"
            )
            con.execute(
                f"CREATE TABLE IF NOT EXISTS request_details AS SELECT {detail_columns} FROM projected LIMIT 0"
            )
            con.execute(f"INSERT INTO core_records SELECT {core_columns} FROM projected ORDER BY _row_id")
            con.execute(
                f"INSERT INTO request_details SELECT {detail_columns} FROM projected ORDER BY _row_id"
            )
            con.execute("DELETE FROM ingest_checkpoint")
            con.execute(
                "INSERT INTO ingest_checkpoint VALUES (?,?,?,?)",
                [signature, next_line, next_offset, sorted(observed)],
            )
            con.execute("COMMIT")
            line_number = next_line
            save_json(
                Path("progress.json"),
                {
                    "worker_pid": os.getpid(),
                    "committed_lines": line_number,
                    "offset_bytes": next_offset,
                    "resumed_from_line": resumed_from,
                },
            )
    Path("batch.tsv").unlink(missing_ok=True)
    if line_number != config["expected_records"] or not line_number:
        raise ValueError(f"Physical-line coverage mismatch or empty source: {line_number}")
    con.execute(f"""CREATE OR REPLACE VIEW core_events AS SELECT *,
        [struct_pack(source_id := {literal(config["source_id"])}, "start" := _row_id, "end" := _row_id)] AS _refs
        FROM core_records""")
    con.execute("""CREATE OR REPLACE VIEW events AS SELECT core_events.*, request_details.* EXCLUDE (_row_id)
                   FROM core_events JOIN request_details USING (_row_id)""")
    rows = con.execute("SELECT count(*) FROM core_records").fetchone()[0]
    if rows != line_number or con.execute("SELECT count(*) FROM request_details").fetchone()[0] != rows:
        raise ValueError("Committed table counts do not match the checkpoint")
    parse_counts = dict(con.execute("SELECT parse_status,count(*) FROM core_records GROUP BY 1").fetchall())
    missing = sorted(observed - set(config["fields"].values()))
    critical = sorted(set(missing) & set(config.get("required_fields", ["authorization", "request_body"])))
    meta = {
        "rows": rows,
        "parse_counts": parse_counts,
        "encoding_repaired_rows": con.execute(
            "SELECT count(*) FROM core_records WHERE _encoding_status='byte_escaped'"
        ).fetchone()[0],
        "schema": [{"name": r[0], "type": r[1]} for r in con.execute("DESCRIBE events").fetchall()],
        "observed_fields": sorted(observed),
        "omitted_fields": missing,
        "missing_critical_fields": critical,
        "field_coverage": "incomplete" if missing else "complete",
        "resumed_from_line": resumed_from,
        "peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
    }
    con.execute("CHECKPOINT")
    con.close()
    save_json(Path("metadata.json"), meta)


if __name__ == "__main__":
    codecs.register_error("irkit_json_bytes", escape_bytes)
    with Path("worker.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        ingest(json.loads(Path(sys.argv[1]).read_text()))
