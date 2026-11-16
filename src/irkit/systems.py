"""Group sources and datasets into logical systems from their directory layout.

A system is the top path segment of a source's original_path (e.g. ucenter, 风险策略系统).
This lets the main Agent divide work by system and time window instead of by log layer,
so a front proxy and its backend application are investigated together. Read-only.
"""

from __future__ import annotations


def _system_of(original_path):
    head = (original_path or "").replace("\\", "/").lstrip("/").split("/", 1)[0]
    return head or "(根目录)"


def system_overview(store):
    systems = {}
    source_system = {}
    for source in store.all("source"):
        name = _system_of(source.get("original_path"))
        source_system[source["id"]] = name
        entry = systems.setdefault(
            name, {"system": name, "sources": 0, "bytes": 0, "records_lf": 0, "datasets": [], "unsupported": 0}
        )
        entry["sources"] += 1
        entry["bytes"] += source.get("size", 0)
        entry["records_lf"] += source.get("record_count_lf", 0)
        if source.get("status") == "unsupported":
            entry["unsupported"] += 1
    for dataset in store.all("dataset"):
        if dataset.get("status") in ("stale", "rejected", "superseded"):
            continue
        for name in {source_system.get(sid) for sid in dataset.get("sources", [])} - {None}:
            systems[name]["datasets"].append(dataset["id"])
    return {
        "systems": sorted(systems.values(), key=lambda s: (-s["bytes"], s["system"])),
        "note": "系统由 original_path 顶层目录推断；按系统×时间窗分派取证，不按日志层拆分。",
    }
