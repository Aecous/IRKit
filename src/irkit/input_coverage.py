"""Derive input coverage from published raw references and explicit exclusions."""

from bisect import bisect_left
from collections import defaultdict

INVALID = {"stale", "rejected", "superseded"}


def add_range(ranges, start, end):
    """Merge overlapping or adjacent physical records without double-counting."""
    index = bisect_left(ranges, (start,))
    if index and ranges[index - 1][1] + 1 >= start:
        index -= 1
    stop = index
    while stop < len(ranges) and ranges[stop][0] <= end + 1:
        start = min(start, ranges[stop][0])
        end = max(end, ranges[stop][1])
        stop += 1
    ranges[index:stop] = [(start, end)]


def input_coverage(store, sources=None, datasets=None):
    sources = list(store.all("source")) if sources is None else sources
    datasets = store.all("dataset") if datasets is None else datasets
    gaps = {obj["source_id"]: obj for obj in store.all("input_gap")}
    parts = defaultdict(list)
    ranges = defaultdict(list)
    for ds in datasets:
        if ds["status"] in INVALID:
            continue
        coverage = defaultdict(list)
        for entry in ds.get("raw_coverage", []):
            coverage[entry["source_id"]].append(entry)
        for sid in ds["sources"]:
            entries = coverage.get(sid, [])
            if entries and not any(part["ranges"] for part in entries):
                continue  # A declared source with zero emitted references is not covered.
            parts[sid].append(ds["id"])
            ranges[sid].extend(part for part in entries if part["ranges"])
    rows = []
    for src in sources:
        sid = src["id"]
        records = src.get("record_count_lf") if src["size"] == 0 else None
        totals = {part["records"] for part in ranges[sid]}
        merged = []
        for part in ranges[sid]:
            for first, last in part["ranges"]:
                add_range(merged, first, last)
        # Only combine ranges expressed in a consistent record coordinate system.
        if len(totals) == 1:
            records = next(iter(totals))
        elif len(totals) > 1:
            records, merged = None, []
        covered = sum(end - start + 1 for start, end in merged)
        if records == 0 or (records is not None and merged == [(1, records)]):
            state = "complete"
        elif merged:
            state = "partial"
        elif parts[sid]:
            state = "unverified"
        else:
            state = "not_processed"
        gap = gaps.get(sid)
        if gap and any(store.get(oid)["status"] in INVALID | {"running"} for oid in gap["attempt_ids"]):
            gap = None
        rows.append(
            dict(
                source_id=sid,
                path=src["original_path"],
                state=state,
                records=records,
                referenced_records=covered if merged or not parts[sid] else None,
                dataset_ids=parts[sid],
                gap=gap,
                duplicate_of=None,
            )
        )
    complete = {
        src["sha256"]: row["source_id"] for src, row in zip(sources, rows) if row["state"] == "complete"
    }
    for src, row in zip(sources, rows):
        if row["state"] != "complete" and src["sha256"] in complete:
            row.update(state="duplicate", duplicate_of=complete[src["sha256"]])
    return rows


def record_input_gap(store, source_id, reason, attempt_ids):
    store.get(source_id, "source")
    if not reason.strip() or len(reason) > 1200 or not 1 <= len(attempt_ids) <= 15:
        raise ValueError(
            "Give a specific gap reason and 1..15 supporting transform/ingest run or dataset IDs"
        )
    for oid in attempt_ids:
        obj = store.get(oid)
        if (
            source_id not in obj.get("sources", [])
            or not (obj["kind"] == "dataset" or obj.get("operation") in {"transform", "ingest_jsonl"})
            or obj["status"] in INVALID | {"running"}
        ):
            raise ValueError(
                "Each reference must be a current dataset or a finished processing attempt for this source"
            )
    data = dict(
        source_id=source_id,
        reason=reason.strip(),
        attempt_ids=list(dict.fromkeys(attempt_ids)),
        status="candidate",
    )
    with store.transaction() as con:
        row = con.execute(
            "SELECT id FROM objects WHERE kind='input_gap' AND json_extract(data,'$.source_id')=?",
            (source_id,),
        ).fetchone()
        if row:
            return store.update(row[0], data, con=con, invalidate=True)
        return store.put("input_gap", data, con=con)
