"""Small transactional case store. No model scheduling lives here."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


def now():
    return datetime.now(timezone.utc).isoformat()


def uid(kind):
    return f"{kind}_{uuid.uuid4().hex[:16]}"


def dumps(value):
    return json.dumps(value, ensure_ascii=False, default=str, allow_nan=False)


class Store:
    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        self.db = self.root / "db/case.sqlite"
        if not (self.root / "case.json").is_file() or not self.db.is_file():
            raise ValueError("Not an initialized case directory")

    @staticmethod
    def initialize(root):
        db = sqlite3.connect(Path(root) / "db/case.sqlite")
        db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE objects (
                id TEXT PRIMARY KEY, kind TEXT NOT NULL, revision INTEGER NOT NULL,
                data TEXT NOT NULL, created TEXT NOT NULL, updated TEXT NOT NULL
            );
            CREATE INDEX objects_kind ON objects(kind);
            CREATE TABLE dependencies (
                child TEXT NOT NULL, parent TEXT NOT NULL,
                PRIMARY KEY(child, parent)
            );
            CREATE TABLE changes (
                seq INTEGER PRIMARY KEY AUTOINCREMENT, object_id TEXT NOT NULL,
                action TEXT NOT NULL, at TEXT NOT NULL, detail TEXT NOT NULL
            );
        """)
        db.close()

    @contextmanager
    def transaction(self):
        con = sqlite3.connect(self.db, timeout=30)
        con.row_factory = sqlite3.Row
        try:
            con.execute("BEGIN IMMEDIATE")
            yield con
            con.commit()
        except BaseException:
            con.rollback()
            raise
        finally:
            con.close()

    def get(self, object_id, kind=None, con=None):
        own = con is None
        con = con or sqlite3.connect(self.db, timeout=30)
        try:
            row = con.execute("SELECT kind, revision, data FROM objects WHERE id=?", (object_id,)).fetchone()
            if not row or (kind and row[0] != kind):
                raise ValueError(f"Unknown {kind or 'object'} in this case: {object_id}")
            return {**json.loads(row[2]), "id": object_id, "kind": row[0], "revision": row[1]}
        finally:
            if own:
                con.close()

    def list(self, kind, limit=100, offset=0):
        if not 1 <= limit <= 500 or offset < 0:
            raise ValueError("Invalid page (limit 1..500, offset >= 0)")
        con = sqlite3.connect(self.db)
        try:
            rows = con.execute(
                "SELECT id FROM objects WHERE kind=? ORDER BY created,id LIMIT ? OFFSET ?",
                (kind, limit, offset),
            ).fetchall()
            return [self.get(row[0], con=con) for row in rows]
        finally:
            con.close()

    def all(self, kind):
        offset = 0
        while page := self.list(kind, 500, offset):
            yield from page
            offset += len(page)

    def counts(self):
        con = sqlite3.connect(self.db)
        try:
            return dict(con.execute("SELECT kind,COUNT(*) FROM objects GROUP BY kind"))
        finally:
            con.close()

    def put(self, kind, data, *, object_id=None, dependencies=(), request_key=None, con=None):
        if con is None:
            with self.transaction() as tx:
                return self.put(
                    kind,
                    data,
                    object_id=object_id,
                    dependencies=dependencies,
                    request_key=request_key,
                    con=tx,
                )
        if request_key:
            if len(request_key) > 160:
                raise ValueError("Submission key exceeds 160 characters")
            con.execute(
                "CREATE TABLE IF NOT EXISTS submissions (key TEXT PRIMARY KEY, hash TEXT, object_id TEXT)"
            )
            digest = hashlib.sha256(
                json.dumps(
                    [kind, data, sorted(set(dependencies))], sort_keys=True, ensure_ascii=False
                ).encode()
            ).hexdigest()
            previous = con.execute(
                "SELECT hash,object_id FROM submissions WHERE key=?", (request_key,)
            ).fetchone()
            if previous:
                if previous[0] != digest:
                    raise ValueError("Submission key conflict: payload changed; use revise_card")
                return self.get(previous[1], con=con)
        object_id = object_id or uid(kind)
        for parent in set(dependencies):
            self.get(parent, con=con)
            if parent == object_id:
                raise ValueError("Self dependency")
        timestamp = now()
        con.execute(
            "INSERT INTO objects VALUES (?,?,1,?,?,?)", (object_id, kind, dumps(data), timestamp, timestamp)
        )
        con.executemany(
            "INSERT INTO dependencies VALUES (?,?)", [(object_id, parent) for parent in set(dependencies)]
        )
        if kind in ("card", "link", "check"):
            self.assert_live_dependencies(object_id, con)
        if request_key:
            con.execute("INSERT INTO submissions VALUES (?,?,?)", (request_key, digest, object_id))
        con.execute(
            "INSERT INTO changes(object_id,action,at,detail) VALUES (?,?,?,?)",
            (object_id, "create", timestamp, dumps(data)),
        )
        return self.get(object_id, con=con)

    def assert_live_dependencies(self, object_id, con):
        ancestors = con.execute(
            """
            WITH RECURSIVE ancestors(id) AS (
                SELECT parent FROM dependencies WHERE child=?
                UNION SELECT d.parent FROM dependencies d JOIN ancestors a ON d.child=a.id
            ) SELECT id FROM ancestors
        """,
            (object_id,),
        ).fetchall()
        for row in ancestors:
            ancestor = self.get(row[0], con=con)
            if ancestor.get("status") in ("stale", "rejected", "superseded"):
                raise ValueError(f"Invalid dependency: {ancestor['id']} is {ancestor['status']}")

    def update(self, object_id, patch, *, expected_revision=None, invalidate=False, con=None):
        if con is None:
            with self.transaction() as tx:
                return self.update(
                    object_id, patch, expected_revision=expected_revision, invalidate=invalidate, con=tx
                )
        old = self.get(object_id, con=con)
        if expected_revision is not None and old["revision"] != expected_revision:
            raise ValueError(f"Revision conflict: expected {expected_revision}, actual {old['revision']}")
        if any(k in patch for k in ("id", "kind", "revision")):
            raise ValueError("Cannot modify object identity")
        data = {k: v for k, v in old.items() if k not in ("id", "kind", "revision")}
        data.update(patch)
        con.execute(
            "UPDATE objects SET data=?, revision=revision+1, updated=? WHERE id=?",
            (dumps(data), now(), object_id),
        )
        con.execute(
            "INSERT INTO changes(object_id,action,at,detail) VALUES (?,?,?,?)",
            (object_id, "update", now(), dumps({"before": old, "patch": patch})),
        )
        if invalidate:
            descendants = con.execute(
                """
                WITH RECURSIVE affected(id) AS (
                    SELECT child FROM dependencies WHERE parent=?
                    UNION SELECT d.child FROM dependencies d JOIN affected a ON d.parent=a.id
                ) SELECT id FROM affected
            """,
                (object_id,),
            ).fetchall()
            for row in descendants:
                obj = self.get(row[0], con=con)
                if obj.get("status") in ("rejected", "superseded"):
                    continue
                if obj["kind"] in ("card", "link"):
                    # A changed premise requires review; it does not erase observed facts.
                    reasons = dict(obj.get("review_causes", {}))
                    reasons[object_id] = self.get(object_id, con=con)["revision"]
                    self.update(
                        obj["id"],
                        {
                            "review_state": "needs_review",
                            "review_causes": reasons,
                            "stale_because": object_id,
                        },
                        con=con,
                    )
                elif obj["kind"] in ("check", "report"):
                    self.update(obj["id"], {"status": "stale", "stale_because": object_id}, con=con)
        return self.get(object_id, con=con)

    def path(self, relative):
        path = (self.root / relative).resolve()
        if not path.is_relative_to(self.root):
            raise ValueError("Artifact path escapes case")
        return path
