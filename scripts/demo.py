"""Deterministic tool-chain demo. Does not call a model or claim autonomous investigation."""

from pathlib import Path

from irkit import board
from irkit.datasets import dataset_row, publish_dataset, query_dataset, run_transform
from irkit.evidence import initialize_case, read_evidence
from irkit.report import render_report
from irkit.store import dumps


def run_demo(cases_dir):
    project = Path(__file__).resolve().parents[1]
    store = initialize_case(
        project / "examples/logs", cases_dir, (project / "examples/background.txt").read_text()
    )
    names = {s["id"]: s["original_path"] for s in store.all("source")}
    code = f"SOURCE_NAMES = {names!r}\n" + (project / "examples/fixture_transform.py").read_text()
    run = run_transform(store, list(names), code)
    if run["status"] != "succeeded":
        raise RuntimeError(run)
    ds = publish_dataset(
        store,
        run["id"],
        "四种合成日志的工具链验证数据",
        {"time_original": "保留各源原始时间字符串", "message": "Java 多行或 Windows 字段"},
        "固定测试脚本：9 个事件；IIS 跳过 4 行注释，XML 事件引用整个 3 行文档；不适用于真实格式。",
        ["SELECT event_kind, count(*) FROM {dataset_id} GROUP BY event_kind"],
    )
    did = ds["id"]
    query = query_dataset(
        store,
        [did],
        f"SELECT n._row_id AS web_row, j._row_id AS app_row, n.request_id "
        f"FROM {did} n JOIN {did} j USING(request_id) "
        "WHERE n.event_kind='nginx' AND j.event_kind='java' AND n.status=500",
    )
    if query["status"] != "succeeded" or len(query["preview"]) != 1:
        raise RuntimeError(query)
    row = query["preview"][0]
    for row_id in (row["web_row"], row["app_row"]):
        for ref in dataset_row(store, did, row_id)["_refs"]:
            read_evidence(store, **ref)
    web = board.submit_card(
        store,
        "POST /api/template 返回 HTTP 500",
        "observation",
        [{"dataset_id": did, "row_id": row["web_row"]}],
        entities=["req-probe"],
    )
    app = board.submit_card(
        store,
        "同 request_id 的 Java 事件记录模板拒绝及多行异常",
        "observation",
        [{"dataset_id": did, "row_id": row["app_row"]}],
        entities=["req-probe"],
    )
    board.submit_link(
        store,
        web["id"],
        app["id"],
        "相同 request_id，时间相符，支持跨层关联；不证明执行成功",
        [{"query_id": query["id"]}],
        inferred=True,
    )
    board.submit_check(
        store,
        "500 请求是否有应用层对应记录？",
        [query["id"]],
        "hits",
        "四份合成日志中的 req-probe",
        "request_id 的可信性来自合成测试设定，不能外推到真实环境",
    )
    report = render_report(
        store,
        "发现请求异常与应用拒绝的关联；现有合成证据不足以证明成功入侵。",
        ["没有主机进程与文件审计", "这是固定脚本工具测试，未验证模型自主分析"],
        ["真实案件应核对请求来源、执行审计和文件变化"],
    )
    return store, ds, report


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    store, dataset, report = run_demo(root / ".validation/demo-cases")
    print(
        dumps(
            {
                "case": str(store.root),
                "dataset_id": dataset["id"],
                "rows": dataset["row_count"],
                "report": str(store.path(report["path"])),
            }
        )
    )
