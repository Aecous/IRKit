"""Start a native timeline investigation with a clean board and a pinned ingestion run."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from irkit import DEFAULT_BUDGET_USD
from irkit.store import Store, now, uid


def data_fields(obj):
    return {key: value for key, value in obj.items() if key not in {"id", "kind", "revision"}}


def prepare(original, run_id, background):
    run = original.get(run_id, "run")
    if run.get("operation") != "ingest_jsonl" or run["status"] != "succeeded":
        raise ValueError("Choose a successful JSONL ingestion run")
    datasets = [original.get(did, "dataset") for did in run["dataset_ids"]]
    if not datasets or any(ds["run_id"] != run_id or ds["status"] == "superseded" for ds in datasets):
        raise ValueError("The selected run must contain current datasets")
    sources = [
        original.get(sid, "source") for sid in sorted({sid for ds in datasets for sid in ds["sources"]})
    ]
    files = [ds["path"] for ds in datasets]
    for source in sources:
        files.append(source["path"])
        if source.get("line_index"):
            files.append(source["line_index"])
    for relative in files:
        path = original.path(relative)
        if not path.is_file() or path.stat().st_mode & 0o222:
            raise ValueError(f"Expected a read-only case artifact: {relative}")

    root = original.root.parent / uid("case_timeline")
    root.mkdir(mode=0o700)
    for directory in ("raw", "db", "datasets", "runs", "reports", "workspace"):
        (root / directory).mkdir(mode=0o700)
    for relative in files:
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        os.link(original.path(relative), destination)
    metadata = json.loads((original.root / "case.json").read_text())
    metadata.update(
        id=root.name,
        created=now(),
        background=background,
        background_status="user_provided_unverified",
        parent_case=original.root.name,
        pinned_ingest_run=run_id,
    )
    (root / "case.json").write_text(json.dumps(metadata, ensure_ascii=False), encoding="utf-8")
    Store.initialize(root)
    snapshot = Store(root)
    with snapshot.transaction() as con:
        for source in sources:
            snapshot.put("source", data_fields(source), object_id=source["id"], con=con)
        snapshot.put(
            "run",
            {
                "operation": "ingest_jsonl",
                "status": "succeeded",
                "dataset_ids": run["dataset_ids"],
                "sources": [source["id"] for source in sources],
                "original_case": original.root.name,
            },
            object_id=run_id,
            con=con,
        )
        for dataset in datasets:
            snapshot.put(
                "dataset",
                data_fields(dataset),
                object_id=dataset["id"],
                dependencies=[run_id, *dataset["sources"]],
                con=con,
            )
    return snapshot


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case_dir", type=Path)
    parser.add_argument("--ingest-run", required=True)
    parser.add_argument("--background", required=True)
    parser.add_argument("--budget", type=float, default=DEFAULT_BUDGET_USD)
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    original = Store(args.case_dir)
    run = original.get(args.ingest_run, "run")
    snapshot = prepare(original, args.ingest_run, args.background)
    prompt = Path(__file__).with_name("timeline_instructions.md").read_text(encoding="utf-8")
    prompt += f"\n锁定入库作业 {run['id']}。可用分区 ID：{json.dumps(run['dataset_ids'])}。\n"
    instruction = snapshot.root / "timeline-instructions.md"
    instruction.write_text(prompt, encoding="utf-8")
    print(f"调查目录：{snapshot.root}\n报告目录：{snapshot.root / 'reports'}", flush=True)
    if not args.prepare_only:
        launcher = Path(__file__).with_name("run_case.py").resolve()
        subprocess.run(
            [
                sys.executable,
                str(launcher),
                str(snapshot.root),
                "--analysis-only",
                "--budget",
                str(args.budget),
                "--instruction-file",
                str(instruction),
            ],
            check=True,
        )


if __name__ == "__main__":
    main()
