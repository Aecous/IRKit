from __future__ import annotations

import gzip
import hashlib
import json
import os
import stat
from pathlib import Path

from .store import Store, dumps, now, uid

MAX_RECORD_BYTES = 2 * 1024 * 1024


class LineIndex:
    """Sparse LF byte index built in the same pass as the evidence hash/copy."""

    def __init__(self, stride=4096):
        self.stride, self.lines, self.position = stride, 0, 0
        self.offsets, self.last = [0], b""

    def feed(self, chunk):
        count = chunk.count(b"\n")
        target = ((self.lines // self.stride) + 1) * self.stride
        cursor, traversed = 0, self.lines
        while target <= self.lines + count:
            for _ in range(target - traversed):
                cursor = chunk.index(b"\n", cursor) + 1
            self.offsets.append(self.position + cursor)
            traversed, target = target, target + self.stride
        self.lines += count
        self.position += len(chunk)
        self.last = chunk[-1:]

    def result(self):
        return {
            "stride": self.stride,
            "offsets": self.offsets,
            "records": self.lines + int(bool(self.position) and self.last != b"\n"),
            "physical_newline": "LF",
        }


def detect_kind(path, original_name):
    with path.open("rb") as stream:
        head = stream.read(8192)
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "text"
    if head.startswith(b"ElfFile\x00"):
        return "evtx"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if b"\x00" in head:
        return "unsupported"
    return "text"


def iter_records(path, kind, encoding="utf-8"):
    """Physical line/record ordinals, bounded record size, strict decoding."""
    if encoding not in ("utf-8", "utf-8-sig", "gb18030", "latin-1", "utf-16", "utf-16-le", "utf-16-be"):
        raise ValueError("Unsupported encoding")
    if kind == "evtx":
        from Evtx.Evtx import Evtx

        with Evtx(str(path)) as log:
            for ordinal, record in enumerate(log.records(), 1):
                text = record.xml()
                if len(text.encode()) > MAX_RECORD_BYTES:
                    raise ValueError(f"EVTX record {ordinal} exceeds size limit")
                yield ordinal, text
    elif kind in ("text", "gzip"):
        opener = gzip.open if kind == "gzip" else open
        with opener(path, "rt", encoding=encoding, errors="strict", newline="") as stream:
            ordinal = 0
            while line := stream.readline(MAX_RECORD_BYTES + 1):
                ordinal += 1
                if len(line) > MAX_RECORD_BYTES:
                    raise ValueError(f"Record {ordinal} exceeds size limit; split source before analysis")
                yield ordinal, line.rstrip("\r\n")
    elif kind == "unsupported" and encoding == "latin-1":
        # Byte-preserving LF records give custom parsers a stable raw reference.
        with open(path, "rb") as stream:
            ordinal = 0
            while line := stream.readline(MAX_RECORD_BYTES + 1):
                ordinal += 1
                if len(line) > MAX_RECORD_BYTES:
                    raise ValueError(f"Binary LF record {ordinal} exceeds 2 MiB")
                yield ordinal, line.removesuffix(b"\n").decode("latin-1")
    else:
        raise ValueError(
            "Unsupported binary format; inspect SOURCE_PATHS in run_transform; "
            "use encoding='latin-1' for byte-preserving LF references"
        )


def initialize_case(source_dir, cases_dir, background=""):
    source_dir = Path(source_dir).expanduser().resolve(strict=True)
    cases_dir = Path(cases_dir).expanduser().resolve()
    if not source_dir.is_dir():
        raise ValueError("Input must be a directory")
    if cases_dir.is_relative_to(source_dir) or source_dir.is_relative_to(cases_dir):
        raise ValueError("Input and case storage must not overlap")
    root = cases_dir / uid("case")
    root.mkdir(parents=True, mode=0o700)
    for name in ("raw", "db", "datasets", "runs", "reports", "workspace"):
        (root / name).mkdir(mode=0o700)
    meta = {
        "id": root.name,
        "created": now(),
        "input_directory": str(source_dir),
        "background": background,
        "background_status": "user_provided_unverified",
        "event_policy_version": 4,
        "status": "ingesting",
        "skipped": [],
        "errors": [],
        "version": 1,
    }
    (root / "case.json").write_text(dumps(meta), encoding="utf-8")
    Store.initialize(root)
    store = Store(root)
    # Do not follow directory or file symlinks, including evidence disguised as config.
    for directory, dirs, files in os.walk(source_dir, followlinks=False):
        for name in list(dirs):
            if (Path(directory) / name).is_symlink():
                meta["skipped"].append(
                    {"path": str((Path(directory) / name).relative_to(source_dir)), "reason": "symlink"}
                )
                dirs.remove(name)
        for name in sorted(files):
            original = Path(directory) / name
            relative = str(original.relative_to(source_dir))
            sid = uid("src")
            destination = root / "raw" / sid
            try:
                fd = os.open(original, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, "rb") as reader:
                    before = os.fstat(reader.fileno())
                    if not stat.S_ISREG(before.st_mode):
                        meta["skipped"].append({"path": relative, "reason": "not regular file"})
                        continue
                    digest = hashlib.sha256()
                    indexer = LineIndex()
                    with destination.open("xb") as writer:
                        while chunk := reader.read(1024 * 1024):
                            digest.update(chunk)
                            indexer.feed(chunk)
                            writer.write(chunk)
                    after = os.fstat(reader.fileno())
                    if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                        after.st_size,
                        after.st_mtime_ns,
                        after.st_ctime_ns,
                    ):
                        raise ValueError("Source changed during copy")
                destination.chmod(0o400)
                kind = detect_kind(destination, name)
                index_metadata = {}
                if kind == "text":
                    idx = indexer.result()
                    index_path = f"raw/{sid}.lines.json"
                    (root / index_path).write_text(dumps(idx))
                    (root / index_path).chmod(0o400)
                    index_metadata = {"line_index": index_path, "record_count_lf": idx["records"]}
                store.put(
                    "source",
                    {
                        "original_path": relative,
                        "path": f"raw/{sid}",
                        "sha256": digest.hexdigest(),
                        "size": before.st_size,
                        "record_kind": kind,
                        "status": "available" if kind != "unsupported" else "unsupported",
                        **index_metadata,
                    },
                    object_id=sid,
                )
            except (OSError, ValueError) as exc:
                destination.unlink(missing_ok=True)
                collection = meta["skipped"] if original.is_symlink() else meta["errors"]
                collection.append({"path": relative, "reason": str(exc)})
    meta["status"] = "ready_with_gaps" if meta["errors"] else "ready"
    (root / "case.json").write_text(dumps(meta), encoding="utf-8")
    return store


def source_records(store, source_id, encoding="utf-8", start=1):
    source = store.get(source_id, "source")
    if source.get("line_index") and encoding in ("utf-8", "utf-8-sig", "gb18030", "latin-1"):
        index = json.loads(store.path(source["line_index"]).read_text())
        block = min((start - 1) // index["stride"], len(index["offsets"]) - 1)
        with store.path(source["path"]).open("rb") as stream:
            stream.seek(index["offsets"][block])
            ordinal = block * index["stride"]
            while line := stream.readline(MAX_RECORD_BYTES + 1):
                ordinal += 1
                if len(line) > MAX_RECORD_BYTES:
                    raise ValueError("Record exceeds 2 MiB")
                if ordinal >= start:
                    yield ordinal, line.decode(encoding, errors="strict").rstrip("\r\n")
    else:
        for ordinal, text in iter_records(store.path(source["path"]), source["record_kind"], encoding):
            if ordinal >= start:
                yield ordinal, text


def read_evidence(store, source_id, start=1, end=20, encoding="utf-8"):
    if type(start) is not int or type(end) is not int or start < 1 or end < start or end - start >= 200:
        raise ValueError("Use a 1-based inclusive range of at most 200 records")
    result, used, truncated = [], 0, False
    for ordinal, text in source_records(store, source_id, encoding, start):
        if ordinal < start:
            continue
        if ordinal > end:
            break
        if used + len(text) > 24000:
            remaining = 24000 - used
            if remaining:
                result.append({"ordinal": ordinal, "text": text[:remaining], "truncated": True})
            truncated = True
            break
        result.append({"ordinal": ordinal, "text": text})
        used += len(text)
    if not result:
        raise ValueError("Requested record does not exist")
    return {
        "source_id": source_id,
        "encoding": encoding,
        "records": result,
        "truncated": truncated,
        "returned_through": result[-1]["ordinal"],
    }


def raw_ref(store, ref, *, counts=None):
    if set(ref) - {"source_id", "start", "end", "encoding"}:
        raise ValueError("Unexpected raw evidence reference fields")
    sid, start, end = ref.get("source_id"), ref.get("start"), ref.get("end")
    if type(start) is not int or type(end) is not int or start < 1 or end < start:
        raise ValueError("Invalid raw evidence range")
    encoding = ref.get("encoding", "utf-8")
    key = (sid, encoding)
    source = store.get(sid, "source")
    if source.get("line_index") and encoding in ("utf-8", "utf-8-sig", "gb18030", "latin-1"):
        if end > source["record_count_lf"]:
            raise ValueError("Evidence range exceeds actual source")
        if counts is not None:
            counts[key] = source["record_count_lf"]
        return sid
    if counts is not None and key not in counts:
        counts[key] = sum(1 for _ in source_records(store, sid, encoding))
    if counts is not None:
        exists = end <= counts[key]
    else:
        exists = False
        for ordinal, _ in source_records(store, sid, encoding):
            if ordinal == end:
                exists = True
                break
    if not exists:
        raise ValueError("Evidence range exceeds actual source")
    return sid


def case_metadata(store):
    return json.loads((store.root / "case.json").read_text())
