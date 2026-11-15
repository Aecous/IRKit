import base64
import gzip
import json
from pathlib import Path

import duckdb

from irkit import decoding
from irkit.evidence import initialize_case


def test_multilayer_and_limits():
    body = json.dumps({"sql": "UPDATE example SET label='x' WHERE id=1"}).encode()
    decoded = decoding.decode(base64.b64encode(gzip.compress(body)))
    assert decoded["chain"] == ["base64", "gzip"]
    assert decoded["sql"]["operation"] == "UPDATE"
    assert decoded["text"] == body.decode()
    assert decoding.decode(gzip.compress(b"x" * 200000))["decode_status"] == "size_limit"
    assert decoding.decode(b"encrypted-opaque-content")["decode_status"] == "unresolved"
    assert decoding.decode(base64.b64encode(b"plain text"), ["base64"])["text"] == "plain text"
    assert decoding.decode(b'{"sql":"CALL unknown()"}')["semantic_status"] == "unclassified"
    assert decoding.decode(body.hex().encode())["chain"] == ["hex"]
    assert decoding.decode(b"%7B%22username%22%3A%22alice%22%7D")["account"] == "alice"
    for username in ("a", "ab", "abc", "alice"):
        encoded = base64.b64encode(json.dumps({"username": username}).encode())
        assert decoding.decode(encoded)["account"] == username


def test_batch_restart_and_filter_coverage(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    body = json.dumps({"sql": "INSERT INTO user (username) VALUES ('alice')"}).encode()
    records = [{"request_body": base64.b64encode(gzip.compress(body)).decode()}, {"request_body": None}]
    (logs / "input.jsonl").write_text("\n".join(json.dumps(x) for x in records) + "\n")
    store = initialize_case(logs, tmp_path / "cases", "")
    sid = store.list("source")[0]["id"]
    target = store.root / "datasets/test.duckdb"
    con = duckdb.connect(str(target))
    con.execute(
        """CREATE TABLE events AS SELECT 1 AS _row_id,'/sql' AS request_path,
      [struct_pack(source_id := ?, start := 1, "end" := 1)] AS _refs""",
        [sid],
    )
    con.execute(
        """INSERT INTO events SELECT 2,'/sql',[struct_pack(source_id := ?, start := 2, "end" := 2)]""", [sid]
    )
    con.close()
    ds = store.put(
        "dataset", {"path": str(Path("datasets/test.duckdb")), "sources": [sid], "status": "provisional"}
    )
    run = decoding.start_decode(store, [ds["id"]], {"request_path": "/sql"})
    assert run["candidate_count"] == 2
    assert decoding.decode_batch(store, run["id"], 1)["status"] == "running"
    result = decoding.decode_batch(store, run["id"], 1)
    assert result["status"] == "succeeded"
    assert result["coverage"] == {"absent": 1, "decoded": 1}
    assert result["overview"]["sql_operations"] == {"INSERT": 1}
    assert result["overview"]["operation_sample_refs"]["INSERT"]["line"] == 1
    empty_page = decoding.read_decoded(store, run["id"], operation="SELECT")
    assert empty_page["matching_total"] == 0 and empty_page["records"] == []
    assert empty_page["overview"]["sql_operations"] == {"INSERT": 1}
    assert empty_page["overview"]["processed_count"] == 2
    assert decoding.decode_batch(store, run["id"], 1)["processed_count"] == 2
    hit = decoding.read_decoded(store, run["id"], operation="INSERT", include_text=True)["records"]
    assert len(hit) == 1 and hit[0]["line"] == 1
    assert hit[0]["sql"]["account_candidate"] == "alice"


def test_event_correlation_and_reconnect(case):
    from irkit import board, telemetry

    task = board.create_task(case, "ir-investigate", "Inspect", "Synthetic", [])
    telemetry.initialize(case)
    telemetry.record(
        case,
        "session_test",
        {
            "type": "assistant",
            "message": {
                "content": [
                    {
                        "type": "tool_use",
                        "id": "native_child",
                        "name": "Agent",
                        "input": {"prompt": "Run task " + task["id"]},
                    }
                ]
            },
        },
    )
    telemetry.record(
        case,
        "session_test",
        {
            "type": "assistant",
            "parent_tool_use_id": "native_child",
            "message": {"content": [{"type": "text", "text": "Inspecting evidence"}]},
        },
    )
    events = telemetry.events(case)
    assert events[1]["task_id"] == task["id"]
    assert events[1]["agent_id"] == "native_child"
    assert len(telemetry.events(case, after=events[0]["seq"])) == 1


def test_ordinary_task_artifacts_and_session_history(case, dataset):
    from irkit import board, telemetry

    task = board.create_task(case, "ir-investigate", "Inspect", "Fixture", [dataset["id"]])
    task = board.update_task(case, task["id"], task["revision"], "running")
    card = board.submit_card(
        case,
        "Observed row",
        "observation",
        [{"dataset_id": dataset["id"], "row_id": 1}],
        task_id=task["id"],
    )
    check = board.submit_check(case, "Inspect", [], "inconclusive", "Fixture", "No audit", task_id=task["id"])
    assert card["task_id"] == check["task_id"] == task["id"]
    assert "followup_task_id" not in card
    telemetry.initialize(case)
    for rid in ("a", "b"):
        telemetry.record(case, rid, {"type": "session_start"})
        telemetry.record(case, rid, {"type": "session_end", "exit_code": 0})
    assert [s["run_id"] for s in telemetry.sessions(case)] == ["b", "a"]
    page = telemetry.history(case, "a", limit=1)
    assert page[0]["event_type"] == "session_end"
    assert telemetry.history(case, "a", before=page[0]["seq"])[0]["event_type"] == "session_start"
    assert telemetry.sessions(case)[0]["ending"]["exit_code"] == 0
