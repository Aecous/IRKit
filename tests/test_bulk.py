import json

from irkit.bulk import ingest_status, start_jsonl_ingest
from irkit.datasets import dataset_row, query_dataset
from irkit.evidence import LineIndex, initialize_case, raw_ref, read_evidence


def test_sparse_index_across_chunks_and_partial_line(tmp_path):
    data = b"one\ntwo\nthree\nfour"
    index = LineIndex(stride=2)
    for i in range(0, len(data), 3):
        index.feed(data[i : i + 3])
    assert index.result() == {"stride": 2, "offsets": [0, 8], "records": 4, "physical_newline": "LF"}
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "a.log").write_text("".join(f"line-{i}\n" for i in range(10000)))
    store = initialize_case(logs, tmp_path / "cases")
    sid = store.list("source")[0]["id"]
    assert read_evidence(store, sid, 8193, 8194)["records"][0]["text"] == "line-8192"
    assert raw_ref(store, {"source_id": sid, "start": 10000, "end": 10000}) == sid


def test_bulk_jsonl_keeps_token_invalid_lines_and_lineage(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    token = "Bearer synthetic-token-preserved-in-full"
    (logs / "events.log").write_text(
        json.dumps({"@timestamp": "2026-10-10T00:00:00+08:00", "authorization": token})
        + '\n\nBAD JSON\n{"authorization":"another"}'
    )
    store = initialize_case(logs, tmp_path / "cases")
    sid = store.list("source")[0]["id"]
    run = start_jsonl_ingest(store, [sid], {"event_time": "@timestamp", "authorization": "authorization"})
    for _ in range(20):
        status = ingest_status(store, run["id"], 1)
        if status["status"] != "running":
            break
    assert status["status"] == "succeeded", status
    ds = store.get(status["dataset_ids"][0])
    assert ds["row_count"] == 4 and ds["parse_counts"] == {"ok": 2, "empty": 1, "invalid_json": 1}
    row = dataset_row(store, ds["id"], 1)
    assert row["authorization"] == token and row["auth_fingerprint"]
    assert row["event_time"] == "2026-10-10T00:00:00+08:00"
    assert dataset_row(store, ds["id"], 4)["_refs"][0]["start"] == 4
    result = query_dataset(store, [ds["id"]], f"SELECT count(*) n FROM {ds['id']}")
    assert result["status"] == "succeeded" and result["preview"][0]["n"] == 4


def test_bulk_preserves_binary_body_row_and_complete_auth(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    raw = b'{"authorization":"Bearer complete-value","body":"zip-\xff-\x02"}\n'
    (logs / "binary-body.log").write_bytes(raw)
    store = initialize_case(logs, tmp_path / "cases")
    sid = store.list("source")[0]["id"]
    run = start_jsonl_ingest(store, [sid], {"authorization": "authorization", "body": "body"})
    for _ in range(20):
        status = ingest_status(store, run["id"], 1)
        if status["status"] != "running":
            break
    assert status["status"] == "succeeded", status
    ds = store.get(status["dataset_ids"][0])
    row = dataset_row(store, ds["id"], 1)
    assert row["authorization"] == "Bearer complete-value"
    assert row["body"] == "zip-ÿ-\x02"
    assert row["_encoding_status"] == "byte_escaped" and ds["encoding_repaired_rows"] == 1
    assert store.path(store.get(sid)["path"]).read_bytes() == raw


def test_bulk_normalizes_core_and_reports_required_projection_gap(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "nginx.log").write_text(
        json.dumps(
            {
                "@timestamp": "2026-10-10T00:00:00+08:00",
                "client_forward": "192.0.2.1, 192.0.2.2",
                "request_uri": "/test?q=%2B&q=second",
                "status": "404",
                "size": "123",
                "request_body": "must remain available",
            }
        )
        + "\n"
    )
    store = initialize_case(logs, tmp_path / "cases")
    sid = store.list("source")[0]["id"]
    run = start_jsonl_ingest(
        store,
        [sid],
        {
            "event_time": "@timestamp",
            "client_forward": "client_forward",
            "request_uri": "request_uri",
            "status": "status",
            "size": "size",
        },
    )
    status = ingest_status(store, run["id"], 10)
    assert status["status"] == "partial", status
    did = status["dataset_ids"][0]
    assert status["field_incomplete_datasets"] == [did]
    assert store.get(did)["missing_critical_fields"] == ["request_body"]
    result = query_dataset(
        store,
        [did],
        f"""SELECT event_time_utc, source_ip_candidate, source_ip_basis,
        request_path, query_raw, status, size FROM {did}_core""",
    )
    assert result["status"] == "succeeded", result
    assert result["preview"] == [
        {
            "event_time_utc": "2026-10-09 16:00:00",
            "source_ip_candidate": "192.0.2.1",
            "source_ip_basis": "unverified_forwarded_first_hop",
            "request_path": "/test",
            "query_raw": "q=%2B&q=second",
            "status": 404,
            "size": 123,
        }
    ]
