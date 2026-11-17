import pytest

from irkit import board, events, integrity, report
from irkit.datasets import publish_dataset, read_query_result, run_transform
from irkit.evidence import initialize_case
from irkit.input_coverage import input_coverage, record_input_gap
from irkit.report_template import event_order, relation_display
from irkit.source_profile import source_profile
from irkit.verification import closure_readiness


def publish(case, sources, code):
    run = run_transform(case, sources, code)
    assert run["status"] == "succeeded", run
    return publish_dataset(case, run["id"], "Coverage fixture", {"kind": "test"}, "Explicit fixture", [])


def test_file_coverage_counts_distinct_records_and_requires_explained_omissions(tmp_path):
    logs = tmp_path / "input"
    logs.mkdir()
    for filename, content in {
        "a.log": "one\ntwo\nthree\n",
        "copy.log": "one\ntwo\nthree\n",
        "c.log": "four\n",
    }.items():
        (logs / filename).write_text(content)
    case = initialize_case(logs, tmp_path / "cases")
    a, c, duplicate = [s["id"] for s in sorted(case.all("source"), key=lambda s: s["original_path"])]
    first = publish(
        case,
        [a, c],
        """
for n in (1, 1, 3):
    emit({"kind":"operation"}, [{"source_id": SOURCE_IDS[0], "start":n, "end":n}])
""",
    )
    coverage = {row["source_id"]: row for row in input_coverage(case)}
    assert coverage[a]["state"] == "partial" and coverage[a]["referenced_records"] == 2
    assert coverage[c]["state"] == "not_processed" and not coverage[c]["dataset_ids"]
    assert coverage[duplicate]["state"] == "not_processed"
    board.create_task(case, "ir-synthesize", "Review", "All input", [], event_policy_version=4)
    assert len([i for i in closure_readiness(case)["issues"] if i["code"] == "INPUT_COVERAGE_PENDING"]) == 3
    publish(case, [a], 'emit({"kind":"followup"}, [{"source_id": SOURCE_IDS[0], "start":2, "end":2}])')
    coverage = {row["source_id"]: row for row in input_coverage(case)}
    assert coverage[a]["state"] == "complete"
    assert coverage[duplicate]["duplicate_of"] == a
    with pytest.raises(ValueError, match="processing attempt"):
        record_input_gap(case, duplicate, "Unavailable", [first["id"]])
    record_input_gap(case, c, "Parser emitted no rows for this input", [first["run_id"]])
    assert closure_readiness(case)["ready"]
    path = report.render_report(case, "Input audit", [], [], "progress")["appendix_path"]
    assert "已验证重复" in case.path(path).read_text()
    assert "Parser emitted no rows" in case.path(path).read_text()


def test_source_profile_surfaces_rare_large_responses_and_validates_report_citations(case):
    sid = case.list("source")[0]["id"]
    ds = publish(
        case,
        [sid],
        """
for n, text in records(SOURCE_IDS[0]):
    emit({"origin":"192.0.2.1, 192.0.2.10", "operation":"usual" if n==1 else "rare",
          "result":"rejected" if n==1 else "ok", "size":3 if n==1 else 16777216},
         [{"source_id": SOURCE_IDS[0], "start":n, "end":n}])
""",
    )
    args = (case, ds["id"], "192.0.2.1", "origin", "forwarded_first", ["operation", "result"])
    truncated = source_profile(*args, response_size_field="size", max_groups=1)
    assert truncated["source_profile"]["matched_rows"] == 2 and truncated["truncated"]
    query = source_profile(*args, response_size_field="size")
    assert query["source_profile"]["total_groups"] == 2
    page = read_query_result(case, query["id"], limit=1)
    assert page["next_offset"] == 1
    rows = page["rows"] + read_query_result(case, query["id"], offset=1)["rows"]
    assert {row["op_0"] for row in rows} == {"rare", "usual"}
    assert next(row for row in rows if row["op_0"] == "rare")["size_rank"] == 1
    zero = source_profile(case, ds["id"], "192.0.2.10", "origin", "forwarded_first", ["operation"])
    assert zero["source_profile"]["matched_rows"] == 0

    task = board.create_task(
        case, "ir-investigate", "Inspect", "All rows", [ds["id"]], event_policy_version=4
    )
    task = board.update_task(case, task["id"], task["revision"], "running")
    ref = {"dataset_id": ds["id"], "row_id": 2}
    question = dict(status="not_applicable", reason="Synthetic fixture only")
    source = dict(address="192.0.2.1", field="origin", match_mode="forwarded_first")
    event = dict(
        title="Uncommon operation",
        environment="lab",
        asset="test",
        observed="An uncommon operation was logged",
        possible_causes=[],
        observed_effects=[],
        potential_impacts=[],
        upstream=question,
        downstream=question,
        claims=[
            dict(
                key="obs",
                statement="An operation was logged",
                level="application",
                evidence=[ref],
                scope=dict(environment="lab", dimensions={}),
            )
        ],
        sources=[source],
        timeline=dict(start="2026-11-13T10:00:01Z", basis="recorded_offset"),
    )
    card = events.submit_event(case, event, [ref], "10:00:01 UTC", task["id"])
    check = board.submit_check(
        case,
        "Entire source distribution",
        [query["id"]],
        "hits",
        "Two matched operations in the partition",
        "Application authorization unknown",
        task_id=task["id"],
    )
    board.update_task(
        case, task["id"], task["revision"], "completed", "Operations observed", [card["id"], check["id"]]
    )
    synth = board.create_task(
        case, "ir-synthesize", "Review", "Fixture", [card["id"]], event_policy_version=4
    )
    synth = board.update_task(case, synth["id"], synth["revision"], "running")

    def final(card):
        integrity.review_delivery(case, synth["id"], {card["id"]: "Verified"}, "Review")
        known = dict(
            text="Operation recorded",
            certainty="confirmed",
            evidence=[dict(object_id=card["id"], revision=card["revision"], claim_key="obs")],
        )
        unknown = dict(text="Not established", certainty="unknown", evidence=[])
        return report.render_report(
            case,
            "Assessment",
            [],
            [],
            report_content=dict(
                scope_note="Fixture", conclusions=[known], impacts=[unknown], recommendations=[unknown],
                attack_chains=[], post_exploitation=[], timeline=[], sources=[]
            ),
        )

    with pytest.raises(ValueError, match="SOURCE_BASELINE_MISSING"):
        final(card)
    event["sources"] = [{**source, "check_ids": [check["id"]]}]
    card = events.revise_event(case, card["id"], card["revision"], event, [], "Attach checked profile")
    out = final(card)
    assert "保存 2/2 组" not in case.path(out["path"]).read_text()
    assert case.get(check["id"])["query_ids"] == [query["id"]]
    case.update(check["id"], {"status": "stale"})
    from irkit.source_profile import source_issues

    assert source_issues(case, [card])[0]["code"] == "SOURCE_CHECK_OUTDATED"


def test_structured_and_legacy_ranges_sort_by_real_instant_and_links_respect_direction(case, dataset):
    event_a = {
        "timeline": events.validate_time(
            dict(start="2026-11-13T18:00:00+08:00", end="2026-11-13T18:00:10+08:00", basis="recorded_offset")
        )
    }
    event_b = {
        "timeline": events.validate_time(
            dict(start="2026-11-13T10:01:00Z", basis="inferred_offset", note="clock comparison")
        )
    }
    with pytest.raises(ValueError, match="precedes start"):
        events.validate_time(
            dict(start="2026-11-13T18:00:00+07:00", end="2026-11-13T10:00:00Z", basis="recorded_offset")
        )
    ref = {"dataset_id": dataset["id"], "row_id": 1}
    question = dict(status="not_applicable", reason="Fixture")
    common = dict(
        environment="lab",
        asset="test",
        observed="An observation",
        possible_causes=[],
        observed_effects=[],
        potential_impacts=[],
        upstream=question,
        downstream=question,
    )
    a = board.submit_card(
        case, "Early event", "observation", [ref], event={**common, **event_a, "title": "Early"}
    )
    b = board.submit_card(
        case, "Late event", "observation", [ref], event={**common, **event_b, "title": "Late"}
    )
    legacy = dict(id="legacy", time_range="2026-11-13T10:00:30Z–2026-11-13T10:00:45Z（UTC）")
    assert [c["id"] for c in sorted([b, legacy, a], key=event_order)] == [a["id"], "legacy", b["id"]]
    with pytest.raises(ValueError, match="reverses"):
        board.submit_link(case, b["id"], a["id"], "Incorrect time order", [ref], relation_type="sequence")
    link = board.submit_link(case, b["id"], a["id"], "Common token", [ref], relation_type="same_session")
    assert relation_display(link) == ("↔", "同会话")
