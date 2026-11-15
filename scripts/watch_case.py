"""Show progress from the case database without displaying log contents."""

import argparse
import json
import sqlite3
import time
from datetime import datetime
from pathlib import Path


class CaseProgress:
    def __init__(self, case_dir: Path):
        self.database = case_dir.resolve() / "db/case.sqlite"
        self.previous = None

    def show(self):
        with sqlite3.connect(f"{self.database.as_uri()}?mode=ro", uri=True) as conn:
            tasks = conn.execute(
                "SELECT id, json_extract(data, '$.role'), json_extract(data, '$.status') "
                "FROM objects WHERE kind='task' ORDER BY created"
            ).fetchall()
            counts = dict(
                conn.execute(
                    "SELECT json_extract(data, '$.status') AS status, count(*) FROM objects "
                    "WHERE kind='run' AND json_extract(data, '$.operation')='query' GROUP BY status"
                )
            )
            latest = conn.execute(
                "SELECT id, json_extract(data, '$.status'), json_extract(data, '$.saved_rows') "
                "FROM objects WHERE kind='run' AND json_extract(data, '$.operation')='query' "
                "ORDER BY updated DESC LIMIT 1"
            ).fetchone()
            artifacts = dict(
                conn.execute(
                    "SELECT kind, count(*) FROM objects WHERE kind IN ('card','check') GROUP BY kind"
                )
            )
            reports = [
                json.loads(row[0])["path"]
                for row in conn.execute("SELECT data FROM objects WHERE kind='report' ORDER BY created")
            ]

        current = tasks, counts, latest, artifacts, reports
        if current == self.previous:
            return
        old_tasks = {item[0]: item[2] for item in self.previous[0]} if self.previous else {}
        old_reports = self.previous[-1] if self.previous else []
        self.previous = current
        stamp = datetime.now().strftime("%H:%M:%S")
        for task_id, role, status in tasks:
            if old_tasks.get(task_id) != status:
                print(f"[{stamp}] 任务 {role} {task_id} → {status}", flush=True)
        query_stats = " / ".join(f"{state} {count}" for state, count in sorted(counts.items())) or "0"
        print(
            f"[{stamp}] 查询 {query_stats} | 卡片 {artifacts.get('card', 0)} | 检查 {artifacts.get('check', 0)}",
            flush=True,
        )
        if latest:
            query_id, state, rows = latest
            row_count = f"，保存 {rows} 行" if rows is not None else ""
            print(f"[{stamp}] 最近查询 {query_id} {state}{row_count}", flush=True)
        for path in reports:
            if path not in old_reports:
                print(f"[{stamp}] 报告 {self.database.parent.parent / path}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case_dir", type=Path)
    parser.add_argument("--follow", action="store_true", help="Keep monitoring until Ctrl-C")
    args = parser.parse_args()
    progress = CaseProgress(args.case_dir)
    try:
        while True:
            progress.show()
            if not args.follow:
                break
            time.sleep(5)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
