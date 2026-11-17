"""Loopback case workbench, explicit user dispatch and case-bound evidence endpoints."""

from __future__ import annotations

import json
import secrets
import sqlite3
import time
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import DEFAULT_BUDGET_USD, decoding, events, evidence, integrity, source_leads, telemetry
from .dispatch import Dispatch
from .store import Store, dumps

ASSETS = Path(__file__).with_name("web_assets")


def snapshot(store):
    with closing(sqlite3.connect(store.db, timeout=30)) as con:
        rows = con.execute(
            "SELECT id,kind,revision,data FROM objects WHERE kind IN ('task','card','check','link','report','run','source_lead') ORDER BY created DESC LIMIT 2000"
        ).fetchall()
        version = con.execute("SELECT coalesce(max(seq),0) FROM changes").fetchone()[0]
    objects = []
    tasks = list(store.all("task"))
    for oid, kind, revision, raw in rows:
        data = json.loads(raw)
        if kind == "run":
            data = {
                k: v
                for k, v in data.items()
                if k not in ("sql", "preview", "stdout_tail", "stderr_tail", "records")
            }
        obj = {**data, "id": oid, "kind": kind, "revision": revision}
        if kind == "card" and obj.get("event"):
            obj["investigation"] = {
                side: events.direction_state(store, obj, side, tasks) for side in ("upstream", "downstream")
            }
        objects.append(obj)
    return {
        "case": json.loads((store.root / "case.json").read_text()),
        "objects": [o for o in objects if o["kind"] != "source_lead"] + source_leads.aggregate(store),
        "version": version,
        "limit": 2000,
        "counts": store.counts(),
    }


def create_server(case_dir, port=8765):
    store = Store(case_dir)
    telemetry.initialize(store)
    dispatch = Dispatch(store.root)
    token = secrets.token_urlsafe(32)

    class Handler(BaseHTTPRequestHandler):
        def trusted_host(self):
            return self.headers.get("Host") in (
                f"127.0.0.1:{self.server.server_port}",
                f"localhost:{self.server.server_port}",
            )

        def do_POST(self):
            origin = self.headers.get("Origin")
            if (
                not self.trusted_host()
                or origin != "http://" + self.headers.get("Host", "")
                or not secrets.compare_digest(self.headers.get("X-IRKit-Token", ""), token)
            ):
                self.send({"error": "请求来源校验失败，请刷新本地工作台"}, status=403)
                return
            if self.path not in ("/api/jobs", "/api/jobs/stop", "/api/workspace"):
                self.send({"error": "Not found"}, status=404)
                return
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if (
                    self.headers.get("Content-Type", "").split(";")[0] != "application/json"
                    or not 0 < size <= 160000
                ):
                    raise ValueError("Expected a bounded JSON request")
                self.connection.settimeout(10)
                data = json.loads(self.rfile.read(size))
                if not isinstance(data, dict):
                    raise ValueError("Expected a JSON object")
                if self.path == "/api/jobs":
                    self.send(dispatch.submit(data), status=202)
                elif self.path == "/api/jobs/stop":
                    self.send(dispatch.stop(data.get("job_id"), data.get("project_id")), status=202)
                else:
                    self.send(
                        dispatch.projects.change(
                            data.get("action"),
                            data.get("kind"),
                            data.get("id"),
                            data.get("name"),
                            data.get("background", ""),
                            dispatch.jobs(),
                        )
                    )
            except RuntimeError as exc:
                self.send({"error": str(exc)}, status=409)
            except (ValueError, TypeError, OSError) as exc:
                self.send({"error": str(exc)}, status=400)

        def log_message(self, format, *args):
            pass

        def send(self, value, content_type="application/json; charset=utf-8", status=200):
            data = value if isinstance(value, bytes) else dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'",
            )
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if not self.trusted_host():
                self.send({"error": "Invalid host"}, status=403)
                return
            parsed = urlparse(self.path)
            args = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            try:
                if parsed.path in (
                    "/",
                    "/app.js",
                    "/workspace.js",
                    "/conversation.js",
                    "/timeline.js",
                    "/events.js",
                    "/sources.js",
                    "/style.css",
                ):
                    name = "index.html" if parsed.path == "/" else parsed.path[1:]
                    kind = (
                        "text/javascript"
                        if name.endswith(".js")
                        else "text/css"
                        if name.endswith(".css")
                        else "text/html"
                    )
                    self.send((ASSETS / name).read_bytes(), kind + "; charset=utf-8")
                    return
                if parsed.path in ("/api/control", "/api/workspace", "/api/job-log"):
                    view = dispatch.projects.view(dispatch.jobs(), args.get("project"), args.get("case"))
                    if parsed.path == "/api/job-log":
                        job = next(
                            (
                                j
                                for j in view["jobs"]
                                if j["id"] == args.get("id")
                                and j["visible"]
                                and j["project_id"] == view["project_id"]
                            ),
                            None,
                        )
                        if not job:
                            raise ValueError("Unknown job in selected project")
                        with (dispatch.directory / (job["id"] + ".log")).open("rb") as log:
                            log.seek(0, 2)
                            size = log.tell()
                            log.seek(max(0, size - 20000))
                            self.send(
                                {
                                    "text": log.read().decode("utf-8", errors="replace"),
                                    "truncated": size > 20000,
                                }
                            )
                    else:
                        if parsed.path == "/api/control":
                            view["jobs"] = [
                                j
                                for j in view["jobs"]
                                if j["visible"] and j["project_id"] == view["project_id"]
                            ]
                        self.send({**view, "token": token, "default_budget": DEFAULT_BUDGET_USD})
                    return
                store = dispatch.case(args.get("case"), args.get("project"))
                telemetry.initialize(store)
                catalog = dispatch.projects.sync(dispatch.jobs())
                visible_sessions = telemetry.sessions(store)
                jobs = dispatch.jobs()
                hidden = dispatch.projects.hidden_sessions(catalog, jobs, store.root, visible_sessions)
                if args.get("run") in hidden:
                    raise ValueError("会话已移入回收站")
                if parsed.path == "/api/snapshot":
                    self.send(snapshot(store))
                elif parsed.path == "/api/object":
                    if args["id"].startswith("source_view_"):
                        obj = next((o for o in source_leads.aggregate(store) if o["id"] == args["id"]), None)
                        if obj is None:
                            raise ValueError("Source aggregation no longer exists; refresh the view")
                    else:
                        obj = store.get(args["id"])
                    if obj["kind"] in ("card", "link", "check", "source_lead"):
                        obj["history"] = integrity.history(store, obj["id"], limit=10)
                    if obj["kind"] == "card" and obj.get("event"):
                        obj["investigation"] = {
                            side: events.direction_state(store, obj, side)
                            for side in ("upstream", "downstream")
                        }
                    self.send(obj)
                elif parsed.path in ("/api/sources", "/api/source-queue"):
                    self.send(
                        source_leads.source_overview(
                            store, int(args.get("limit", 30)), int(args.get("offset", 0))
                        )
                    )
                elif parsed.path == "/api/object-history":
                    self.send(integrity.history(store, args["id"], int(args.get("offset", 0)), 10))
                elif parsed.path == "/api/events":
                    if args.get("run"):
                        self.send(
                            telemetry.history(
                                store,
                                args["run"],
                                int(args["before"]) if args.get("before") else None,
                                agent_id=args.get("agent"),
                            )
                        )
                    else:
                        self.send(
                            [
                                r
                                for r in telemetry.events(store, max(0, int(args.get("after", 0))))
                                if r["run_id"] not in hidden
                            ]
                        )
                elif parsed.path == "/api/sessions":
                    self.send([s for s in visible_sessions if s["run_id"] not in hidden])
                elif parsed.path == "/api/session-context":
                    self.send(telemetry.context(store, args["run"]))
                elif parsed.path == "/api/raw":
                    self.send(
                        evidence.read_evidence(
                            store, args["source"], int(args["line"]), int(args["line"]), "latin-1"
                        )
                    )
                elif parsed.path == "/api/decoded":
                    self.send(
                        decoding.read_decoded(
                            store,
                            args["id"],
                            int(args.get("offset", 0)),
                            operation=args.get("operation"),
                            contains=args.get("contains"),
                            include_text=args.get("text") == "1",
                        )
                    )
                elif parsed.path == "/api/report":
                    obj = store.get(args["id"], "report")
                    part, format_name = args.get("part", "main"), args.get("format", "json")
                    if part not in {"main", "appendix"} or format_name not in {"json", "markdown", "html"}:
                        raise ValueError("Unknown report part or format")
                    key = ("appendix_" if part == "appendix" else "") + (
                        "html_path" if format_name == "html" else "path"
                    )
                    if key not in obj:
                        raise ValueError(
                            "This historical report has no separate export for the requested part"
                        )
                    path = store.path(obj[key])
                    if format_name == "json":
                        self.send({"report": obj, "text": path.read_text(), "part": part})
                    else:
                        data = path.read_bytes()
                        self.send_response(200)
                        self.send_header(
                            "Content-Type",
                            ("text/html" if format_name == "html" else "text/markdown") + "; charset=utf-8",
                        )
                        self.send_header("Content-Disposition", f'attachment; filename="{path.name}"')
                        self.send_header(
                            "Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'"
                        )
                        self.send_header("Content-Length", str(len(data)))
                        self.end_headers()
                        self.wfile.write(data)
                elif parsed.path == "/api/stream":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Cache-Control", "no-cache")
                    self.end_headers()
                    after = int(self.headers.get("Last-Event-ID") or args.get("after", 0))
                    for _ in range(25):
                        try:
                            dispatch.case(store.root.name, args.get("project"))
                        except ValueError:
                            break
                        jobs = dispatch.jobs()
                        catalog = dispatch.projects.sync(jobs)
                        hidden = dispatch.projects.hidden_sessions(
                            catalog, jobs, store.root, telemetry.sessions(store)
                        )
                        rows = telemetry.events(store, after)
                        for row in rows:
                            if row["run_id"] in hidden:
                                after = row["seq"]
                                continue
                            self.wfile.write(
                                f"id: {row['seq']}\nevent: runtime\ndata: {dumps(row)}\n\n".encode()
                            )
                            after = row["seq"]
                        self.wfile.write(b"event: refresh\ndata: {}\n\n")
                        self.wfile.flush()
                        time.sleep(1)
                else:
                    self.send({"error": "Not found"}, status=404)
            except (BrokenPipeError, ConnectionResetError):
                pass
            except (ValueError, KeyError, OSError) as exc:
                self.send({"error": str(exc)}, status=400)

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def serve(case_dir, port=8765):
    server = create_server(case_dir, port)
    print(f"IRKit 查看页 http://127.0.0.1:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
