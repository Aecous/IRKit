"""Convert registered EVTX evidence into queryable Windows event datasets."""

from xml.etree import ElementTree as ET

from .datasets import run_transform_batches
from .store import dumps

TRANSFORM = """from irkit.evtx_ingest import event_fields

for sid in SOURCE_IDS:
    for ordinal, xml in records(sid):
        emit(event_fields(sid, ordinal, xml), [{"source_id": sid, "start": ordinal, "end": ordinal}])
"""


def event_fields(source_id, ordinal, xml):
    row = dict.fromkeys(
        (
            "provider", "provider_guid", "channel", "computer", "event_id", "event_qualifiers",
            "event_record_id", "time_utc", "version", "level", "task", "opcode", "keywords",
            "execution_process_id", "execution_thread_id", "activity_id", "related_activity_id",
            "security_user_id", "user_data_xml",
        )
    )
    row.update(source_id=source_id, ordinal=ordinal, event_data_json="[]", parse_status="xml_error")
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return row

    event_data = root.find("{*}EventData")
    if event_data is not None:
        row["event_data_json"] = dumps([
            {
                "tag": element.tag.rsplit("}", 1)[-1],
                "name": element.get("Name"),
                "value": element.text,
                **({"xml": ET.tostring(element, encoding="unicode").strip()} if len(element) else {}),
            }
            for element in event_data
        ])
    user_data = root.find("{*}UserData")
    if user_data is not None:
        row["user_data_xml"] = ET.tostring(user_data, encoding="unicode").strip()

    system = root.find("{*}System")
    if system is None:
        row["parse_status"] = "missing_system"
        return row
    row["parse_status"] = "ok"
    for key in ("channel", "computer", "version", "level", "task", "opcode", "keywords"):
        row[key] = system.findtext(f"{{*}}{key.title()}")
    row["event_id"] = system.findtext("{*}EventID")
    row["event_record_id"] = system.findtext("{*}EventRecordID")
    attributes = (
        ("Provider", {"provider": "Name", "provider_guid": "Guid"}),
        ("EventID", {"event_qualifiers": "Qualifiers"}),
        ("TimeCreated", {"time_utc": "SystemTime"}),
        ("Execution", {"execution_process_id": "ProcessID", "execution_thread_id": "ThreadID"}),
        ("Correlation", {"activity_id": "ActivityID", "related_activity_id": "RelatedActivityID"}),
        ("Security", {"security_user_id": "UserID"}),
    )
    for tag, fields in attributes:
        element = system.find(f"{{*}}{tag}")
        if element is not None:
            for column, attribute in fields.items():
                row[column] = element.get(attribute)
    return row


def ingest_evtx(store, source_ids=None, workers=2, batch_size=5, timeout=0):
    if type(batch_size) is not int or batch_size < 1:
        raise ValueError("Batch size must be a positive integer")
    if source_ids is None:
        source_ids = sorted(s["id"] for s in store.all("source") if s["record_kind"] == "evtx")
    if not source_ids:
        raise ValueError("No EVTX sources selected")
    for sid in source_ids:
        if store.get(sid, "source")["record_kind"] != "evtx":
            raise ValueError(f"Source {sid} is not a registered EVTX file")
    return run_transform_batches(
        store,
        [source_ids[i:i + batch_size] for i in range(0, len(source_ids), batch_size)],
        TRANSFORM,
        "Windows events from registered EVTX sources",
        {
            "time_utc": "Original System/TimeCreated/@SystemTime",
            "event_id": "Windows event ID as text; interpret within provider and channel",
            "event_record_id": "Identifier from the Windows event, separate from file ordinal",
            "ordinal": "One-based physical record ordinal within source_id; used by raw evidence references",
            "event_data_json": "Ordered EventData entries with tag, name, value and XML for nested entries",
            "user_data_xml": "Provider-specific UserData subtree as XML",
            "parse_status": "ok, xml_error or missing_system; rows with XML issues remain in the dataset",
        },
        "Strict binary reads. A native parse error fails its batch. XML issues are retained and labeled.",
        [
            "SELECT provider, channel, event_id, count(*) FROM {dataset_id} GROUP BY ALL",
            "SELECT source_id, ordinal, time_utc, computer, event_record_id, _refs FROM {dataset_id} "
            "WHERE parse_status = 'ok' ORDER BY time_utc LIMIT 20",
        ],
        workers,
        timeout,
    )
