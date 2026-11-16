"""Card-quality guards: reject placeholder/test cards; dedupe reworded same-window nodes."""

import pytest

from irkit import board, events
from irkit.events import is_placeholder_title, normalized_title


def ev(title, observed, env="lab"):
    return dict(
        title=title, environment=env, asset="host-a", observed=observed,
        possible_causes=[], observed_effects=[], potential_impacts=[],
        upstream=dict(question="q", priority="optional", status="open", reason="later"),
        downstream=dict(question="q", priority="optional", status="open", reason="later"),
    )


def running(case, dataset):
    t = board.create_task(case, "ir-investigate", "Find", "Fixture", [dataset["id"]], event_policy_version=1)
    board.update_task(case, t["id"], t["revision"], "running")
    return t["id"]


def test_placeholder_detector_unit():
    for t in ("测试事件", "测试事件2", "diagnostic event", "temporary validation probe", "test", "probe"):
        assert is_placeholder_title(t), t
    # Real titles must not be flagged, including ones mentioning a test account/env.
    for t in ("141.164.107.155 对 /ucenter 端点枚举并登录成功 8 次",
              "测试环境管理员账号被口令喷洒后成功登录",   # Chinese, >8 chars → not placeholder
              "test001 account enumerated via getUserBySystemId"):
        assert not is_placeholder_title(t), t


def test_submit_rejects_placeholder_card(case, dataset):
    tid = running(case, dataset)
    ref = {"dataset_id": dataset["id"], "row_id": 1}
    with pytest.raises(ValueError, match="占位/测试卡"):
        events.submit_event(case, ev("测试事件", "x"), [ref], "2026-01-01T00:00:00+08:00", tid)
    # Same placeholder-ish title but with a substantive observed is allowed.
    ok = events.submit_event(
        case, ev("diagnostic event", "2026-01-05 02:59 +08:00 来源 1.2.3.4 对 /ucenter 枚举 4699 路径"),
        [ref], "2026-01-01T00:00:00+08:00", tid,
    )
    assert ok["id"]


def test_near_duplicate_same_window_is_blocked(case, dataset):
    tid = running(case, dataset)
    ref = {"dataset_id": dataset["id"], "row_id": 1}
    obs = "2026-01-05 来源 1.2.3.4 对 /risksight 枚举，产生 44,904 个 404 的扫描行为记录"
    a = events.submit_event(case, ev("外部客户端对 /risksight 枚举，产生 44,904 个 404", obs),
                            [ref], "win1", tid)
    assert a["id"]
    # Digit/punctuation-only reword, same env + same time window → blocked as duplicate.
    with pytest.raises(ValueError, match="疑似重复事件"):
        events.submit_event(case, ev("外部客户端对 /risksight 枚举，产生 44904个404。", obs),
                            [ref], "win1", tid)
    # Different time window → allowed (distinct node).
    b = events.submit_event(case, ev("外部客户端对 /risksight 枚举，产生 44904个404。", obs),
                            [ref], "win2", tid)
    assert b["id"] != a["id"]


def test_normalized_title_collapses_digits_and_punct():
    assert normalized_title("A 44,904 个 404！") == normalized_title("A 44904个404")
    assert normalized_title("foo-bar 12") != normalized_title("foo baz 12")
