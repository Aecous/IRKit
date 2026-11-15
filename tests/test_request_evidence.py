import gzip
import json

import pytest

from irkit.evidence import initialize_case
from irkit.request_evidence import MAX_DECODED_BYTES, inspect_requests


def test_request_inspection_uses_original_bytes_and_preserves_row_references(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()

    def gz(value):
        return gzip.compress(json.dumps(value).encode(), mtime=0).decode("latin-1")

    # Write an actual binary-byte representation within JSON strings, like the case input.
    bodies = [
        json.dumps({"name": "zuul.routes.example.path", "value": "/private/**"}),
        gz(
            {
                "sql": "INSERT/*comment*/ INTO `app`.`user` (email,username,secret) "
                "VALUES ('a@example.invalid','audit01', CONCAT('secret',',','value'))"
            }
        ),
        gz({"sql": "UPDATE app.user SET active=1 WHERE username='audit01'"}),
        json.dumps({"username": "audit01", "password": "example-secret"}),
        gz({"large": "x" * MAX_DECODED_BYTES}),
        "\x1f\x8binvalid",
    ]
    rows = [
        json.dumps(
            {
                "domain": "example.invalid",
                "request_uri": "/secret/token",
                "status": 200,
                "authorization": "Bearer example-secret",
                "request_body": body,
            },
            ensure_ascii=False,
        )
        for body in bodies
    ]
    (logs / "requests.log").write_bytes(("\n".join(rows) + "\n").encode("latin-1"))
    store = initialize_case(logs, tmp_path / "cases")
    sid = store.list("source")[0]["id"]
    refs = [{"source_id": sid, "start": i, "end": i} for i in range(1, len(rows) + 1)]
    result = inspect_requests(store, refs)
    route, insert, update, login, oversize, invalid = result["records"]
    assert route["route_config_submission"] == {"route_id": "example", "property": "path"}
    assert insert["sql"] == {"operation": "INSERT", "table": "app.user", "account_candidate": "audit01"}
    assert update["sql"] == {"operation": "UPDATE", "table": "app.user", "account_candidate": "audit01"}
    assert login["account_candidate"] == "audit01"
    assert oversize["decode_status"] == "size_limit"
    assert invalid["decode_status"] == "failed"
    assert [row["_refs"][0] for row in result["records"]] == refs
    rendered = json.dumps(result)
    assert all(
        value not in rendered for value in ("example-secret", "/secret/token", "/private/**", "CONCAT")
    )
    with pytest.raises(ValueError, match="single physical row"):
        inspect_requests(store, [{"source_id": sid, "start": 1, "end": 2}])
