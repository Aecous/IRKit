import json
from types import SimpleNamespace

from irkit import dispatch, telemetry
from irkit.cli import launch_arguments
from irkit.completion import assess, checkpoint, legacy_assessment
from irkit.store import now


def report_delivery(case):
    path = case.root / "reports/test.md"
    path.write_text("Synthetic report: no confirmed attack")
    report = case.put("report", dict(path="reports/test.md", status="draft"))
    task = case.put("task", dict(role="ir-synthesize", status="completed", artifact_ids=[report["id"]]))
    return report, task


def test_zero_exit_with_stopped_workers_and_no_report_is_incomplete(case):
    telemetry.initialize(case)
    base = checkpoint(case)
    task = case.put("task", dict(role="ir-investigate", status="running"))
    telemetry.record(case, "session_test", dict(type="result", is_error=False))
    telemetry.record(
        case,
        "session_test",
        dict(type="system", subtype="task_notification", status="stopped", tool_use_id="child"),
    )
    outcome = assess(case, **base)
    assert outcome["status"] == "incomplete"
    assert outcome["unfinished_task_ids"] == [task["id"]]
    assert outcome["stopped_agent_ids"] == ["child"]
    assert not outcome["report_ids"]


def test_delivery_requires_this_runs_report_and_completed_synthesis(case):
    telemetry.initialize(case)
    report_delivery(case)  # Old report must not satisfy a new run.
    case.put("task", dict(role="ir-investigate", status="running"))  # Unrelated old task.
    base = checkpoint(case)
    telemetry.record(case, "new", dict(type="result", is_error=False))
    assert assess(case, **base)["status"] == "incomplete"
    report, task = report_delivery(case)
    result = assess(case, **base)
    assert result["status"] == "completed"
    assert result["report_ids"] == [report["id"]]
    case.update(task["id"], dict(status="running"))
    assert assess(case, **base)["status"] == "incomplete"
    case.update(task["id"], dict(status="completed"))
    case.update(report["id"], dict(status="stale"))
    assert assess(case, **base)["status"] == "incomplete"


def test_missing_report_file_and_model_failure(case):
    telemetry.initialize(case)
    base = checkpoint(case)
    report, _ = report_delivery(case)
    (case.root / report["path"]).unlink()
    telemetry.record(case, "new", dict(type="result", is_error=False))
    assert assess(case, **base)["status"] == "incomplete"
    telemetry.record(case, "new", dict(type="result", is_error=True, subtype="error_max_budget_usd"))
    assert assess(case, **base)["status"] == "failed"
    assert "error_max_budget_usd" in assess(case, **base)["error"]


def test_event_workflow_requires_native_synthesis_delivery(case):
    telemetry.initialize(case)
    base = checkpoint(case)
    _, task = report_delivery(case)
    case.update(task["id"], {"event_policy_version": 1})
    telemetry.record(case, "new", dict(type="result", is_error=False))
    assert "独立综合" in assess(case, **base)["error"]

    def call(actor, name, inputs, tool_id):
        telemetry.record(
            case,
            "new",
            dict(
                type="assistant",
                parent_tool_use_id=actor,
                message=dict(content=[dict(type="tool_use", id=tool_id, name=name, input=inputs)]),
            ),
        )

    call(None, "Agent", {"subagent_type": "ir-synthesize", "prompt": task["id"]}, "reviewer")
    call("reviewer", "mcp__ir__render_report", {"delivery": "final"}, "render")
    # A role label or a report call alone is not delivery by that independent worker.
    assert assess(case, **base)["status"] == "incomplete"
    call("reviewer", "mcp__ir__update_task", {"task_id": task["id"], "status": "completed"}, "complete")
    assert assess(case, **base)["status"] == "completed"


def test_dispatch_keeps_incomplete_outcome_from_launcher(case, monkeypatch):
    path = case.root / "job.json"
    dispatch.save(
        path, dict(mode="current", case_dir=str(case.root), budget=1, background="", analysis_only=True)
    )

    def run(*args, **kwargs):
        telemetry.record(case, "new", dict(type="result", is_error=False))
        telemetry.record(
            case,
            "new",
            dict(
                type="session_end",
                exit_code=0,
                reason="finished",
                outcome=dict(status="incomplete", error="取证尚未完成"),
            ),
        )
        return SimpleNamespace(returncode=2)

    monkeypatch.setattr(dispatch.subprocess, "run", run)
    dispatch.execute(path)
    assert json.loads(path.read_text())["status"] == "incomplete"


def test_native_wait_configuration(case, monkeypatch):
    monkeypatch.setattr("irkit.cli.provider_configuration", lambda: ({}, None))
    monkeypatch.setattr("irkit.cli.shutil.which", lambda _: "/fake/claude")
    _, env, _ = launch_arguments(case, print_mode=True)
    assert env["CLAUDE_CODE_DISABLE_BACKGROUND_TASKS"] == "1"
    assert env["CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS"] == "0"


def test_legacy_job_reconciles_without_borrowing_future_report(case):
    telemetry.initialize(case)
    created = now()
    telemetry.record(case, "old", dict(type="result", is_error=False))
    end = now()
    report_delivery(case)
    result = legacy_assessment(case, dict(created=created, updated=end, exit_code=0))
    assert result["status"] == "incomplete"


def test_context_handles_text_content_and_keeps_agent_names_across_pages(case):
    telemetry.initialize(case)
    telemetry.record(case, "new", dict(type="user", message=dict(content="a text instruction")))
    telemetry.record(
        case,
        "new",
        dict(
            type="assistant",
            message=dict(
                content=[
                    dict(
                        type="tool_use",
                        id="child",
                        name="Agent",
                        input=dict(subagent_type="ir-investigate", description="UAT investigation"),
                    )
                ]
            ),
        ),
    )
    for i in range(110):
        telemetry.record(case, "new", dict(type="system", subtype="heartbeat"))
    assert all(e["event_type"] != "assistant" for e in telemetry.history(case, "new"))
    assert (
        telemetry.context(case, "new")[0]["payload"]["message"]["content"][0]["input"]["description"]
        == "UAT investigation"
    )
