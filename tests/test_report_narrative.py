"""Readable authored reports retain evidence contracts without exporting workflow internals."""

import json
import re
import threading
import urllib.request

import pytest

from irkit import board, report
from irkit.report_export import write_html_pair
from irkit.report_template import validate
from irkit.web import create_server


@pytest.fixture
def narrative(case, dataset):
    card = board.submit_card(
        case, "An audit recorded an action.", "observation", [{"dataset_id": dataset["id"], "row_id": 1}]
    )
    ref = {"object_id": card["id"], "revision": card["revision"]}
    finding = dict(
        text="A process started; transfer completion is unknown.", certainty="possible", evidence=[ref]
    )
    unknown = dict(
        text="The available records do not establish the original entry.", certainty="unknown", evidence=[]
    )
    content = dict(
        scope_note="Lab / 2026-11-13 UTC. Based on existing results.",
        conclusions=[finding],
        impacts=[unknown],
        recommendations=[unknown],
        attack_chains=[
            dict(
                title="Observed activity on host-a",
                scope="host-a / UTC",
                summary=finding,
                steps=[finding],
                connections=[unknown],
            )
        ],
        post_exploitation=[dict(finding, text="Created C:\\Temp\\sample.bin; <script> is log text.")],
        timeline=[dict(time="2026-11-13 10:00:00 UTC", source="unknown", target="host-a", activity=finding)],
        sources=[dict(address="192.0.2.1", role="Observed peer", activity=finding)],
    )
    return card, content


def test_report_and_separate_appendix_keep_citations_and_readability(case, dataset, narrative, monkeypatch):
    monkeypatch.setenv("IRKIT_REVIEW_MODE", "off")
    card, content = narrative
    other = board.submit_card(
        case, "UNRELATED INTERNAL DETAIL", "observation", [{"dataset_id": dataset["id"], "row_id": 2}]
    )
    case.update(other["id"], dict(review_state="needs_review"))
    artifact = report.render_report(
        case, "Authored report", ["Missing network transfer evidence"], [], report_content=content
    )
    body = case.path(artifact["path"]).read_text()
    appendix = case.path(artifact["appendix_path"]).read_text()
    html = case.path(artifact["html_path"]).read_text()
    appendix_html = case.path(artifact["appendix_html_path"]).read_text()
    assert [line for line in body.splitlines() if line.startswith("## ")] == [
        "## 1. 事件概述",
        "## 2. 攻击链路还原",
        "## 3. 后渗透操作与影响",
        "## 4. 攻击时间线与来源",
        "## 5. 调查局限与处置建议",
    ]
    for value in [
        "UNRELATED INTERNAL DETAIL",
        "未决提示",
        "EVIDENCE_REVIEW_PENDING",
        "```mermaid",
        "needs_review",
    ]:
        assert value not in body and value not in appendix
    assert card["id"] not in body and card["id"] in appendix
    assert "SHA-256" in appendix and "原始行号 1–1" in appendix
    assert "Original" not in body
    assert re.search(r"\[E-001\]\(report_[a-f0-9]{16}\.evidence.md#e-001\)", body)
    assert ".evidence.html#e-001" in html and 'id="e-001"' in appendix_html
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "C:\\Temp\\sample.bin" in html  # Markdown escapes don't leak into readable HTML.
    assert "<strong>可能</strong>：" in html
    assert "交付阻塞" not in html
    assert artifact["readiness"]["review_pending"]
    for key in ["path", "appendix_path", "html_path", "appendix_html_path"]:
        assert case.path(artifact[key]).stat().st_mode & 0o777 == 0o600


def test_chinese_named_html_exports_link_to_html_appendix(tmp_path):
    main = tmp_path / "中文报告.md"
    appendix = tmp_path / "中文报告.evidence.md"
    main.write_text("[E-001](中文报告.evidence.md#e-001)", encoding="utf-8")
    appendix.write_text("## E-001\n\n原始证据", encoding="utf-8")
    write_html_pair(main, appendix)
    html = main.with_suffix(".html").read_text()
    assert ".evidence.html#e-001" in html
    assert ".evidence.md" not in html


@pytest.mark.parametrize("location", ["summary", "step", "connection", "post", "timeline", "source"])
def test_every_narrative_section_rejects_stale_citation(case, narrative, location):
    card, content = narrative
    # Only the indicated region references the stale revision; all other references remain current.
    content = json.loads(json.dumps(content))
    locations = dict(
        summary=content["attack_chains"][0]["summary"],
        step=content["attack_chains"][0]["steps"][0],
        connection=content["attack_chains"][0]["connections"][0],
        post=content["post_exploitation"][0],
        timeline=content["timeline"][0]["activity"],
        source=content["sources"][0]["activity"],
    )
    locations[location]["evidence"] = [dict(object_id=card["id"], revision=0)]
    with pytest.raises(ValueError, match="current reviewed"):
        validate(case, content, require_narrative=True)


def test_old_summary_cannot_satisfy_new_final_template(case, narrative):
    _, content = narrative
    for key in ["attack_chains", "post_exploitation", "timeline", "sources"]:
        content.pop(key)
    validate(case, content)  # Legacy/progress report compatibility.
    with pytest.raises(ValueError, match="five-chapter narrative"):
        validate(case, content, require_narrative=True)


def test_export_endpoints_return_separate_parts_and_downloads(case, narrative):
    _, content = narrative
    artifact = report.render_report(
        case, "Available findings", [], [], delivery="progress", report_content=content
    )
    server = create_server(case.root, 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}/api/report?id={artifact['id']}"
    try:
        main = json.load(urllib.request.urlopen(url))
        appendix = json.load(urllib.request.urlopen(url + "&part=appendix"))
        assert main["part"] == "main" and appendix["part"] == "appendix"
        assert "事件概述" in main["text"] and "SHA-256" not in main["text"]
        assert "SHA-256" in appendix["text"]
        with urllib.request.urlopen(url + "&format=html") as response:
            assert response.headers["Content-Disposition"].startswith("attachment;")
            assert response.headers["Content-Type"].startswith("text/html")
            assert '<html lang="zh-CN">' in response.read().decode()
        with pytest.raises(urllib.error.HTTPError):
            urllib.request.urlopen(url + "&part=../../case.json")
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_report_only_uses_real_supervisor_without_reopening_investigation(case, narrative, tmp_path):
    import os
    import subprocess
    import sys
    from pathlib import Path

    from irkit import telemetry
    from irkit.completion import assess

    _, content = narrative
    baseline_task = board.create_task(case, "ir-investigate", "Existing unresolved question", "host-a", [])
    before_task = case.get(baseline_task["id"])
    content_path = tmp_path / "content.json"
    content_path.write_text(json.dumps(content))
    fake = tmp_path / "claude"
    fake.write_text(
        "#!"
        + sys.executable
        + "\n"
        + """
import json,os,sys,asyncio
from pathlib import Path
from irkit.store import Store
from irkit.mcpserver import build_server
assert sys.argv[sys.argv.index('--tools') + 1] == ''
assert '--agents' not in sys.argv
assert os.environ['IRKIT_TASK_MODE'] == 'report'
assert '不创建或派发子 Agent' in sys.argv[sys.argv.index('--append-system-prompt')+1]
store=Store(Path.cwd().parent)
server=build_server(store.root)
names={t.name for t in asyncio.run(server.list_tools())}
assert {'case_context','list_objects','get_object','render_report','read_dataset_row'} <= names
assert not names & {'create_task','query','run_transform','submit_card','revise_event','start_jsonl_ingest','closure_readiness'}
context=json.loads(asyncio.run(server.call_tool('case_context', {}))[0].text)
assert context['task_mode']=='report'
assert 'tasks' not in context and 'sources' not in context and 'datasets' not in context
from irkit.report import render_report
r=render_report(store,'Saved findings',[],[],report_content=json.loads(Path(os.environ['TEST_CONTENT']).read_text()))
assert r['task_mode']=='report' and r['delivery']=='progress' and r['status']=='generated'
print(json.dumps({'type':'result','is_error':False}),flush=True)
"""
    )
    fake.chmod(0o700)
    result = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).resolve().parents[1] / "scripts/run_case.py"),
            str(case.root),
            "--report-only",
        ],
        env={
            **os.environ,
            "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
            "CLAUDE_CONFIG_DIR": str(tmp_path / "empty"),
            "IRKIT_REVIEW_MODE": "full",
            "TEST_CONTENT": str(content_path),
        },
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    ending = telemetry.sessions(case)[0]["ending"]["outcome"]
    assert ending["status"] == "completed" and ending["task_mode"] == "report"
    assert case.get(baseline_task["id"]) == before_task
    assert case.counts()["task"] == 1
    # The writing session cannot satisfy normal investigation closure or an empty later writing run.
    assert assess(case, task_mode="report", after_event=10**9, after_change=10**9)["status"] == "incomplete"


def test_report_context_pages_background_without_large_inventories(case, monkeypatch):
    import asyncio

    from irkit.mcpserver import build_server

    # Even large task summaries/source inventories must not enter the report overview.
    case.put("task", dict(role="ir-investigate", status="completed", summary="INTERNAL_DETAIL" * 10000))
    meta = json.loads((case.root / "case.json").read_text())
    meta["background"] = "背景材料" * 1800
    (case.root / "case.json").write_text(json.dumps(meta, ensure_ascii=False))
    text = ""
    offset = 0
    while True:
        page = board.report_case_context(case, offset)
        assert len(json.dumps(page, ensure_ascii=False).encode()) < 9000
        assert not {"tasks", "sources", "datasets", "closure_readiness"} & page.keys()
        text += page["background"]
        offset = page["next_background_offset"]
        if offset is None:
            break
    assert text == meta["background"]
    with pytest.raises(ValueError):
        board.report_case_context(case, -1)
    monkeypatch.setenv("IRKIT_TASK_MODE", "report")
    assert "closure_readiness" not in {t.name for t in asyncio.run(build_server(case.root).list_tools())}
    monkeypatch.setenv("IRKIT_TASK_MODE", "investigation")
    assert "closure_readiness" in {t.name for t in asyncio.run(build_server(case.root).list_tools())}
    assert "tasks" in board.case_context(case)
