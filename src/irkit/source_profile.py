"""Evidence query for all operations of a source in one explicitly selected partition."""

import ipaddress

from .datasets import query_dataset
from .integrity import pending
from .source_leads import INVALID


def source_profile(
    store,
    dataset_id,
    address,
    field,
    match_mode,
    operation_fields,
    time_field=None,
    response_size_field=None,
    max_groups=100000,
):
    dataset = store.get(dataset_id, "dataset")
    if dataset["status"] in INVALID or not 1 <= max_groups <= 100000:
        raise ValueError("Use a current dataset and max_groups 1..100000")
    ip = ipaddress.ip_address(address)
    if getattr(ip, "scope_id", None) is not None:
        raise ValueError("Normalize scoped IPv6 addresses in the dataset before grouping")
    address = str(ip)
    if match_mode not in ("exact", "forwarded_first"):
        raise ValueError("Use exact or forwarded_first; normalize other source representations first")
    if not 1 <= len(operation_fields) <= 5 or len(set(operation_fields)) != len(operation_fields):
        raise ValueError("Supply 1..5 distinct operation fields (e.g. method, operation/path, outcome)")
    columns = {col["name"] for col in dataset["schema"]}
    required = {field, *operation_fields} | {x for x in (time_field, response_size_field) if x}
    if missing := required - columns:
        raise ValueError(f"Dataset {dataset_id} lacks columns {sorted(missing)}")

    def identifier(name):
        return '"' + name.replace('"', '""') + '"'

    source = f"CAST({identifier(field)} AS VARCHAR)"
    if match_mode == "forwarded_first":
        source = f"split_part({source}, ',', 1)"
    groups = [f"CAST({identifier(name)} AS VARCHAR) AS op_{idx}" for idx, name in enumerate(operation_fields)]
    group_names = ", ".join(f"op_{idx}" for idx in range(len(groups)))
    # Keep the original clock representations: this tool does not assign a timezone.
    raw_time = f"CAST({identifier(time_field)} AS VARCHAR)" if time_field else "NULL::VARCHAR"
    size = f"TRY_CAST({identifier(response_size_field)} AS BIGINT)" if response_size_field else "NULL::BIGINT"
    sql = f"""WITH matched AS (
        SELECT {", ".join(groups)}, {raw_time} AS source_time, {size} AS response_size
        FROM {dataset_id} WHERE trim({source}) = '{address}'
    ), grouped AS (
        SELECT {group_names}, COUNT(*)::BIGINT AS records,
               MIN(source_time) AS first_time_text, MAX(source_time) AS last_time_text,
               COUNT(source_time) AS rows_with_time, MAX(response_size) AS max_response_size,
               COUNT(response_size) AS rows_with_response_size, MIN(response_size) AS min_response_size
        FROM matched GROUP BY {group_names}
    ), ranked AS (
        SELECT *, SUM(records) OVER ()::BIGINT AS matched_rows, COUNT(*) OVER () AS total_groups,
               ROW_NUMBER() OVER (ORDER BY records DESC, {group_names}) AS volume_rank,
               ROW_NUMBER() OVER (ORDER BY max_response_size DESC NULLS LAST, records DESC, {group_names}) AS size_rank
        FROM grouped
    )
    SELECT * FROM ranked ORDER BY LEAST(volume_rank, size_rank), volume_rank, size_rank"""
    scope = dict(
        address=address,
        field=field,
        match_mode=match_mode,
        dataset_id=dataset_id,
        operation_fields=operation_fields,
        time_field=time_field,
        response_size_field=response_size_field,
        scope="all matching rows in this dataset; no operation or time filter",
    )
    return query_dataset(store, [dataset_id], sql, max_groups, source_profile=scope)


def source_issues(store, cards):
    issues = []
    for card in cards:
        event = card.get("event", {})
        if not event.get("timeline"):
            issues.append(
                dict(
                    code="EVENT_TIME_UNDECLARED",
                    object_id=card["id"],
                    action="Record structured start/end with offset basis, or explain unknown time",
                )
            )
        sources = event.get("sources", [])
        if not sources and not event.get("source_limitation"):
            issues.append(
                dict(
                    code="SOURCE_UNDECLARED",
                    object_id=card["id"],
                    action="Record actual source fields or state the evidence-based visibility limit",
                )
            )
        for source in sources:
            baseline = False
            outdated = []
            for cid in source.get("check_ids", []):
                check = store.get(cid, "check")
                if check["status"] in INVALID or pending(check):
                    outdated.append(cid)
                    continue
                for qid in check["query_ids"]:
                    run = store.get(qid, "run")
                    scope = run.get("source_profile", {})
                    if (
                        run["status"] == "succeeded"
                        and scope.get("all_groups_saved")
                        and scope.get("matched_rows", 0) > 0
                        and all(scope.get(key) == source[key] for key in ("address", "field", "match_mode"))
                        and store.get(scope["dataset_id"], "dataset")["status"] not in INVALID
                    ):
                        baseline = True
            if outdated or not baseline:
                issues.append(
                    dict(
                        code="SOURCE_CHECK_OUTDATED" if outdated else "SOURCE_BASELINE_MISSING",
                        object_id=card["id"],
                        address=source["address"],
                        field=source["field"],
                        check_ids=outdated,
                        action="Attach an ordinary current check with a complete operation profile for this source",
                    )
                )
    return issues
