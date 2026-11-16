"""Fresh investigations sharing frozen data, without copying prior analysis or sessions."""

import json
import os
import shutil
from pathlib import Path

from .store import Store, now, uid


def fresh_investigation(original, background, destination=None, dataset_ids=None):
    datasets = [d for d in original.all("dataset") if d["status"] not in ("stale", "superseded", "rejected")]
    if dataset_ids is not None:
        if not dataset_ids or not set(dataset_ids).issubset({d["id"] for d in datasets}):
            raise ValueError("Selected data snapshot is no longer available")
        datasets = [d for d in datasets if d["id"] in dataset_ids]
    if not datasets:
        raise ValueError("没有可复用的已发布数据集")
    sources = [original.get(sid, "source") for sid in sorted({sid for d in datasets for sid in d["sources"]})]
    files = {d["path"] for d in datasets}
    for source in sources:
        files.add(source["path"])
        if source.get("line_index"):
            files.add(source["line_index"])
    for relative in files:
        path = original.path(relative)
        if not path.is_file() or path.stat().st_mode & 0o222:
            raise ValueError(f"Only immutable data can be reused: {relative}")
    root = Path(destination or original.root.parent) / uid("case_investigation")
    root.mkdir(mode=0o700, parents=True)
    try:
        for folder in ("raw", "db", "datasets", "runs", "reports", "workspace"):
            (root / folder).mkdir(mode=0o700)
        for relative in files:
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            os.link(original.path(relative), target)
        meta = json.loads((original.root / "case.json").read_text())
        meta.update(
            id=root.name,
            created=now(),
            background=background,
            background_status="user_provided_unverified",
            parent_case=original.root.name,
            pinned_dataset_ids=[d["id"] for d in datasets],
            analysis_policy="fresh_event_investigation",
            # The user explicitly selects frozen partitions; this is not a new full-input intake.
            event_policy_version=3,
        )
        (root / "case.json").write_text(json.dumps(meta, ensure_ascii=False))
        Store.initialize(root)
        result = Store(root)

        def fields(o):
            return {k: v for k, v in o.items() if k not in {"id", "kind", "revision"}}

        with result.transaction() as con:
            for source in sources:
                result.put("source", fields(source), object_id=source["id"], con=con)
            for rid in {d.get("run_id") for d in datasets} - {None}:
                old = original.get(rid, "run")
                result.put(
                    "run",
                    {
                        "operation": old["operation"],
                        "status": "succeeded",
                        "dataset_ids": [d["id"] for d in datasets if d.get("run_id") == rid],
                        "original_case": original.root.name,
                    },
                    object_id=rid,
                    con=con,
                )
            for dataset in datasets:
                result.put(
                    "dataset",
                    fields(dataset),
                    object_id=dataset["id"],
                    dependencies=[
                        *dataset["sources"],
                        *([dataset["run_id"]] if dataset.get("run_id") else []),
                    ],
                    con=con,
                )
        return result
    except Exception:
        shutil.rmtree(root)
        raise
