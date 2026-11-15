import importlib.util
from pathlib import Path

import pytest

from irkit import board


def test_four_log_formats_keep_multiline_provenance(tmp_path):
    path = Path(__file__).resolve().parents[1] / "scripts/demo.py"
    spec = importlib.util.spec_from_file_location("demo", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    case, ds, report = module.run_demo(tmp_path / "cases")
    assert ds["row_count"] == 9
    cards = case.list("card")
    assert len(cards) == 2
    assert "不足以证明成功入侵" in case.path(report["path"]).read_text()
    from irkit.datasets import dataset_row

    java = dataset_row(case, ds["id"], cards[1]["evidence"][0]["row_id"])
    assert java["_refs"][0]["start"] == 2 and java["_refs"][0]["end"] == 5
    assert java["time_original"] == "2026-11-13T18:01:02+08:00"


def test_idempotent_card_retry_and_conflict(case):
    sid = case.list("source")[0]["id"]
    ref = [{"source_id": sid, "start": 1, "end": 1}]
    a = board.submit_card(case, "one", "observation", ref, submission_key="task1:card1")
    b = board.submit_card(case, "one", "observation", ref, submission_key="task1:card1")
    assert a["id"] == b["id"] and len(case.list("card")) == 1
    with pytest.raises(ValueError, match="Submission key conflict"):
        board.submit_card(case, "different", "observation", ref, submission_key="task1:card1")


def test_context_pages_are_size_bounded_and_report_becomes_stale(case):
    sid = case.list("source")[0]["id"]
    ref = [{"source_id": sid, "start": 1, "end": 1}]
    cards = [board.submit_card(case, f"{i}:" + "x" * 5900, "observation", ref) for i in range(8)]
    context = board.board_context(case, limit=50)
    assert len(context["cards"]) < 8 and context["next_offset"] == len(context["cards"])
    rest = board.board_context(case, offset=context["next_offset"], limit=50)
    assert rest["cards"][0]["id"] == cards[len(context["cards"])]["id"]
    from irkit.report import render_report

    report = render_report(case, "test only", [], [])
    board.revise_card(case, cards[0]["id"], 1, "corrected", ref, "test")
    assert case.get(report["id"])["status"] == "stale"
