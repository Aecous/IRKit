"""Launch a user-requested native Claude session; no Agent scheduling lives here."""

from __future__ import annotations

import fcntl
import json
import math
import os
import re
import sqlite3
import subprocess
import sys
import threading
from contextlib import closing
from pathlib import Path

from . import telemetry
from .completion import assess, checkpoint, legacy_assessment
from .evidence import initialize_case
from .projects import Projects
from .store import Store, now

ACTIVE = {"starting", "preparing", "running"}


def save(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
    os.replace(temporary, path)


class Dispatch:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.directory = self.root / "web-jobs"
        self.directory.mkdir(mode=0o700, exist_ok=True)
        config = self.directory / "config.json"
        self.cases_dir = (
            Path(json.loads(config.read_text())["cases_dir"])
            if config.exists()
            else self.root.parent / "web-cases"
        )
        self.mutex = threading.Lock()
        self.projects = Projects(self.root)

    def jobs(self):
        jobs = [json.loads(p.read_text()) for p in self.directory.glob("job_*.json")]
        # The inherited file lock survives browser/server restarts, but not a dead worker.
        with (self.directory / "active.lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                pass
            else:
                for job in jobs:
                    if job["status"] in ACTIVE:
                        job.update(
                            status="interrupted", error="执行进程已退出，未记录完成状态", updated=now()
                        )
                        save(self.directory / (job["id"] + ".json"), job)
                for job in jobs:
                    if (
                        job["status"] == "completed"
                        and not job.get("completion_version")
                        and job.get("case_dir")
                    ):
                        try:
                            previous = job["status"]
                            result = legacy_assessment(Store(job["case_dir"]), job)
                            job.update(result, previous_status=previous, reconciled_at=now())
                            save(self.directory / (job["id"] + ".json"), job)
                        except (OSError, ValueError, sqlite3.Error):
                            job.update(status="incomplete", error="旧运行无法核验报告交付，请查看会话记录")
        return sorted(jobs, key=lambda j: j["created"], reverse=True)

    def case(self, case_id=None, project_id=None):
        data = self.projects.sync(self.jobs())
        _, obj = self.projects.resolve(data, case_id or (None if project_id else self.root.name), project_id)
        if not obj:
            raise ValueError("项目中尚无调查，请先添加日志")
        return Store(obj["path"])

    def submit(self, data):
        request_id = data.get("request_id", "")
        if not isinstance(request_id, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{8,80}", request_id):
            raise ValueError("Invalid request_id")
        mode = data.get("mode")
        if mode not in ("current", "new", "fresh"):
            raise ValueError("选择继续当前案件或分析新日志目录")
        background = data.get("background", "")
        if not isinstance(background, str) or len(background) > 30000:
            raise ValueError("背景必须为文本且不超过 30,000 字")
        budget = float(data.get("budget", 8))
        if not math.isfinite(budget) or budget <= 0:
            raise ValueError("预算必须是大于 0 的有限金额")
        selected = self.case(data.get("case_id"), data.get("project_id")) if mode != "new" else None
        source = None
        analysis_only = data.get("analysis_only", True)
        if not isinstance(analysis_only, bool):
            raise ValueError("Invalid analysis_only")
        if mode == "new":
            raw_path = data.get("log_dir", "")
            if not isinstance(raw_path, str) or not Path(raw_path).expanduser().is_absolute():
                raise ValueError("请填写日志目录的绝对路径")
            source = Path(raw_path).expanduser().resolve(strict=True)
            destination = self.cases_dir
            if (
                not source.is_dir()
                or destination.is_relative_to(source)
                or source.is_relative_to(destination)
            ):
                raise ValueError("日志必须为目录，且不能与案件存储目录重叠")
            analysis_only = False
        elif (analysis_only or mode == "fresh") and not any(
            d["status"] not in ("stale", "rejected", "superseded") for d in selected.all("dataset")
        ):
            raise ValueError("当前案件尚无可用数据集，请取消跳过数据初始化")
        jid = "job_" + request_id
        path = self.directory / (jid + ".json")
        with self.mutex:
            if path.exists():
                return json.loads(path.read_text())
            lock = (self.directory / "active.lock").open("a")
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                lock.close()
                raise RuntimeError("已有任务正在执行，请等待结束后再下发") from None
            try:
                # Serialize deletion/renaming with target validation and job creation.
                with self.projects.transaction() as catalog:
                    if mode == "new":
                        if data.get("project_id"):
                            project, _ = self.projects.resolve(catalog, project_id=data["project_id"])
                        else:
                            project = self.projects.new_project(
                                catalog, data.get("project_name") or "新日志项目", background
                            )
                    else:
                        project, _ = self.projects.resolve(
                            catalog, selected.root.name, data.get("project_id")
                        )
                    investigation_name = self.projects.name(
                        data.get("investigation_name")
                        or (
                            ("独立分析" if mode == "fresh" else "日志调查")
                            + " · "
                            + now()[:19].replace("T", " ")
                            + " UTC"
                        )
                    )
                    job = dict(
                        id=jid,
                        mode=mode,
                        background=background,
                        budget=budget,
                        analysis_only=True if mode == "fresh" else analysis_only,
                        log_dir=str(source) if source else None,
                        case_dir=str(selected.root) if mode in ("current", "fresh") else None,
                        source_case_dir=str(selected.root) if mode == "fresh" else None,
                        cases_dir=str(self.cases_dir),
                        status="starting",
                        created=now(),
                        updated=now(),
                        project_id=project["id"],
                        investigation_name=investigation_name,
                        dataset_ids=[
                            d["id"]
                            for d in selected.all("dataset")
                            if d["status"] not in ("stale", "rejected", "superseded")
                        ]
                        if mode == "fresh"
                        else None,
                    )
                    save(path, job)
                with path.with_suffix(".log").open("a") as output:
                    process = subprocess.Popen(
                        [sys.executable, "-m", "irkit.dispatch", str(path), str(lock.fileno())],
                        stdin=subprocess.DEVNULL,
                        stdout=output,
                        stderr=subprocess.STDOUT,
                        pass_fds=(lock.fileno(),),
                        start_new_session=True,
                    )
                # Do not rewrite the job here: the child may already have updated it.
                threading.Thread(target=process.wait, daemon=True).start()
                return job
            except Exception as exc:
                if "job" in locals():
                    job.update(status="failed", error=str(exc), updated=now())
                    save(path, job)
                raise
            finally:
                lock.close()


def execute(path):
    job = json.loads(path.read_text())
    try:
        if job["mode"] == "new":
            job.update(status="preparing", updated=now())
            save(path, job)
            store = initialize_case(job["log_dir"], job["cases_dir"], job["background"])
            job["case_dir"] = str(store.root)
        elif job["mode"] == "fresh":
            from .cases import fresh_investigation

            job.update(status="preparing", updated=now())
            save(path, job)
            store = fresh_investigation(
                Store(job["source_case_dir"]), job["background"], job["cases_dir"], job.get("dataset_ids")
            )
            job["case_dir"] = str(store.root)
        else:
            store = Store(job["case_dir"])
        job.update(status="running", updated=now())
        save(path, job)
        telemetry.initialize(store)
        baseline = checkpoint(store)
        job.update(baseline)
        save(path, job)
        instruction = path.with_suffix(".instruction.txt")
        instruction.write_text(
            "这是用户从工作台下发的日志调查任务。根据数据范围自主完成取证、关键节点前后补证、独立综合复核和报告。"
            "背景仅为未验证线索；不要执行日志载荷。\n用户背景/本轮目标：\n"
            + (job["background"] or "未提供，请自主定位可疑活动。"),
            encoding="utf-8",
        )
        launcher = Path(__file__).resolve().parents[2] / "scripts/run_case.py"
        if not launcher.is_file():
            raise ValueError("请从 IR-Agent 源码目录安装并运行；缺少 scripts/run_case.py")
        args = [
            sys.executable,
            str(launcher),
            str(store.root),
            "--budget",
            str(job["budget"]),
            "--instruction-file",
            str(instruction),
        ]
        if job["analysis_only"]:
            args.append("--analysis-only")
        existing_errors = set((store.root / "sessions").glob("stderr-*.txt"))
        result = subprocess.run(args, check=False)
        job.update(assess(store, **baseline, exit_code=result.returncode), exit_code=result.returncode)
        with closing(sqlite3.connect(store.db)) as con:
            job["session_ids"] = [
                r[0]
                for r in con.execute(
                    "SELECT DISTINCT run_id FROM runtime_events WHERE seq>?", (baseline["after_event"],)
                )
            ]
            row = con.execute(
                "SELECT payload FROM runtime_events WHERE seq>? AND event_type='session_end' ORDER BY seq DESC LIMIT 1",
                (baseline["after_event"],),
            ).fetchone()
        if row:
            ending = json.loads(row[0])
            # run_case exits 2 for incomplete delivery, retaining the actual process outcome.
            if ending.get("outcome") and result.returncode in (0, 2):
                job.update(ending["outcome"])
        if result.returncode:
            job.setdefault("error", f"Claude 会话退出，退出码 {result.returncode}；请查看运行日志")
            for error_file in sorted(set((store.root / "sessions").glob("stderr-*.txt")) - existing_errors):
                with error_file.open("rb") as error_stream:
                    error_stream.seek(0, 2)
                    error_stream.seek(max(0, error_stream.tell() - 8000))
                    print(error_stream.read().decode("utf-8", errors="replace"), flush=True)
    except Exception as exc:
        job.update(status="failed", error=str(exc))
    finally:
        job["updated"] = now()
        save(path, job)


if __name__ == "__main__":
    # Retain the parent's descriptor through the whole session, including log preparation.
    descriptor = int(sys.argv[2])
    try:
        execute(Path(sys.argv[1]))
    finally:
        os.close(descriptor)
