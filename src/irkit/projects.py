"""Workbench-only project index. Case stores and immutable evidence stay where they are."""

import fcntl
import json
from contextlib import contextmanager
from pathlib import Path

from .store import Store, now, uid

ACTIVE = {"starting", "preparing", "running"}


class Projects:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.directory = self.root / "web-jobs"
        self.directory.mkdir(exist_ok=True)
        self.path = self.directory / "projects.json"

    @contextmanager
    def transaction(self):
        with (self.directory / "projects.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            data = (
                json.loads(self.path.read_text())
                if self.path.exists()
                else dict(version=1, projects={}, investigations={}, runs={})
            )
            before = json.dumps(data, sort_keys=True)
            yield data
            if json.dumps(data, sort_keys=True) != before or not self.path.exists():
                temporary = self.path.with_suffix(".tmp")
                temporary.write_text(json.dumps(data, ensure_ascii=False))
                temporary.replace(self.path)

    @staticmethod
    def name(value):
        if not isinstance(value, str) or not value.strip() or len(value.strip()) > 120:
            raise ValueError("名称不能为空，最多 120 个字符")
        return value.strip()

    @staticmethod
    def new_project(data, name, background=""):
        name = Projects.name(name)
        if not isinstance(background, str) or len(background) > 30000:
            raise ValueError("项目背景最多 30,000 个字符")
        obj = dict(id=uid("project"), name=name, background=background, created=now(), deleted_at=None)
        data["projects"][obj["id"]] = obj
        return obj

    def sync(self, jobs):
        """Import only registered workbench cases, using explicit lineage, never report semantics."""
        with self.transaction() as data:
            cases = data["investigations"]
            if self.root.name not in cases:
                project = self.new_project(data, "历史日志项目")
                cases[self.root.name] = dict(
                    id=self.root.name,
                    project_id=project["id"],
                    path=str(self.root),
                    name="初始调查",
                    created=json.loads((self.root / "case.json").read_text()).get("created", ""),
                    deleted_at=None,
                )
            pending = sorted(jobs, key=lambda j: j["created"])
            for job in pending:
                path = Path(job["case_dir"]).resolve() if job.get("case_dir") else None
                if not path or not (path / "case.json").is_file():
                    if job.get("project_id") in data["projects"]:
                        data["runs"].setdefault(
                            job["id"],
                            dict(id=job["id"], project_id=job["project_id"], case_id=None, deleted_at=None),
                        )
                    continue
                cid = path.name
                if cid not in cases:
                    meta = json.loads((path / "case.json").read_text())
                    parent_id = (
                        Path(job["source_case_dir"]).name
                        if job.get("source_case_dir")
                        else meta.get("parent_case")
                    )
                    pid = job.get("project_id")
                    if not pid:
                        pid = cases.get(parent_id, {}).get("project_id")
                    if pid not in data["projects"]:
                        project = self.new_project(data, "历史调查 · " + job["created"][:10])
                        pid = project["id"]
                    cases[cid] = dict(
                        id=cid,
                        path=str(path),
                        project_id=pid,
                        name=job.get("investigation_name")
                        or ("独立分析" if job["mode"] == "fresh" else "日志调查")
                        + " · "
                        + job["created"][:16].replace("T", " "),
                        created=meta.get("created", job["created"]),
                        deleted_at=None,
                    )
                record = data["runs"].setdefault(job["id"], dict(id=job["id"], deleted_at=None))
                record.update(project_id=cases[cid]["project_id"], case_id=cid)
            return data

    def resolve(self, data, case_id=None, project_id=None):
        if case_id:
            obj = data["investigations"].get(case_id)
            if not obj or obj.get("deleted_at"):
                raise ValueError("Unknown case; investigation is unavailable or in trash")
            if project_id and obj["project_id"] != project_id:
                raise ValueError("案件不属于所选项目")
            project_id = obj["project_id"]
        else:
            project_id = project_id or data["investigations"][self.root.name]["project_id"]
            candidates = [
                c
                for c in data["investigations"].values()
                if c["project_id"] == project_id and not c.get("deleted_at")
            ]
            obj = max(candidates, key=lambda c: c["created"]) if candidates else None
        project = data["projects"].get(project_id)
        if not project or project.get("deleted_at"):
            raise ValueError("项目不存在或已移入回收站")
        return project, obj

    def change(self, action, kind=None, object_id=None, name=None, background="", jobs=()):
        self.sync(jobs)
        with self.transaction() as data:
            if action == "create":
                return self.new_project(data, name, background)
            collection = {"project": "projects", "investigation": "investigations", "run": "runs"}.get(kind)
            if not collection or object_id not in data[collection]:
                raise ValueError("Unknown project/investigation/run")
            obj = data[collection][object_id]
            if action == "rename":
                obj["name"] = self.name(name)
            elif action in ("trash", "restore"):
                if action == "trash":
                    current_jobs = [json.loads(p.read_text()) for p in self.directory.glob("job_*.json")]
                    for job in current_jobs:
                        run = data["runs"].get(
                            job["id"],
                            dict(
                                project_id=job.get("project_id"),
                                case_id=Path(job["case_dir"]).name if job.get("case_dir") else None,
                            ),
                        )
                        affected = (
                            job["id"] == object_id
                            if kind == "run"
                            else run.get("case_id") == object_id
                            if kind == "investigation"
                            else run.get("project_id") == object_id
                        )
                        # A fresh job pins an existing case until preparation has completed.
                        if kind == "investigation" and job.get("source_case_dir"):
                            affected |= Path(job["source_case_dir"]).name == object_id
                        if affected and job["status"] in ACTIVE:
                            raise RuntimeError("调查仍在运行，结束后才能移入回收站")
                elif kind != "project":
                    if data["projects"][obj["project_id"]].get("deleted_at"):
                        raise ValueError("请先恢复所属项目")
                    if (
                        kind == "run"
                        and obj.get("case_id")
                        and data["investigations"][obj["case_id"]].get("deleted_at")
                    ):
                        raise ValueError("请先恢复所属调查")
                obj["deleted_at"] = now() if action == "trash" else None
            else:
                raise ValueError("Unsupported action")
            obj["updated"] = now()
            return obj

    @staticmethod
    def visible_run(data, job_id):
        obj = data["runs"].get(job_id)
        return bool(
            obj
            and not obj.get("deleted_at")
            and not data["projects"][obj["project_id"]].get("deleted_at")
            and (not obj.get("case_id") or not data["investigations"][obj["case_id"]].get("deleted_at"))
        )

    @staticmethod
    def hidden_sessions(data, jobs, case_dir, sessions):
        hidden = set()
        for job in jobs:
            if job.get("case_dir") != str(case_dir) or Projects.visible_run(data, job["id"]):
                continue
            if "session_ids" in job:
                hidden.update(job["session_ids"])
            else:
                # Legacy jobs have no explicit session links; use both run boundary and time.
                hidden.update(
                    s["run_id"]
                    for s in sessions
                    if s["first_seq"] > job.get("after_event", -1)
                    and job["created"] <= s["started"] <= job["updated"]
                )
        return hidden

    def view(self, jobs, project_id=None, case_id=None):
        data = self.sync(jobs)
        try:
            project, case = self.resolve(data, case_id, project_id)
        except ValueError:
            if project_id or case_id:
                raise
            available = [p for p in data["projects"].values() if not p.get("deleted_at")]
            project, case = self.resolve(data, project_id=available[0]["id"]) if available else (None, None)
        investigations = []
        for c in data["investigations"].values():
            item = dict(c)
            try:
                store = Store(c["path"])
                ds = [
                    d for d in store.all("dataset") if d["status"] not in ("stale", "rejected", "superseded")
                ]
                item.update(
                    dataset_count=len(ds),
                    card_count=store.counts().get("card", 0),
                    row_count=sum(d.get("row_count", 0) for d in ds),
                    data_versions=[
                        dict(
                            id=d["id"], description=d.get("description", ""), row_count=d.get("row_count", 0)
                        )
                        for d in ds
                    ],
                )
            except (OSError, ValueError):
                item.update(dataset_count=0, card_count=0, row_count=0, data_versions=[], unavailable=True)
            attached = [
                j
                for j in jobs
                if data["runs"].get(j["id"], {}).get("case_id") == c["id"] and self.visible_run(data, j["id"])
            ]
            investigations_only = [j for j in attached if j.get("mode") != "report"]
            item["latest_status"] = investigations_only[0]["status"] if investigations_only else "idle"
            report_jobs = [j for j in attached if j.get("mode") == "report"]
            item["latest_report_status"] = report_jobs[0]["status"] if report_jobs else None
            item["active"] = any(
                j["status"] in ACTIVE
                for j in jobs
                if data["runs"].get(j["id"], {}).get("case_id") == c["id"]
                or j.get("source_case_dir") == c["path"]
            )
            investigations.append(item)
        enriched = [
            {**j, **data["runs"].get(j["id"], {}), "visible": self.visible_run(data, j["id"])} for j in jobs
        ]
        return dict(
            projects=list(data["projects"].values()),
            investigations=investigations,
            jobs=enriched,
            project_id=project["id"] if project else None,
            case_id=case["id"] if case else None,
            active_job=next((j for j in enriched if j["status"] in ACTIVE), None),
        )
