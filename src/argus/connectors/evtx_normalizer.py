"""Normalizer for events extracted from Windows .evtx files.

EVTX-Attack-Samples ships raw .evtx (binary event logs). The evtx library
parses each record to a dict shaped like Windows EventLog XML->JSON, where
the useful fields live under System (EventID, Channel, Computer) and
EventData (Image, CommandLine, TargetImage, etc). This normalizer maps
that shape into ARGUS's NormalizedEventData.

Source id: "evtx".
"""

from datetime import UTC, datetime
from typing import Any

from argus.domain.events import NormalizedEventData


def _get(event_data: dict[str, Any], *keys: str) -> str | None:
    for k in keys:
        v = event_data.get(k)
        if v:
            return str(v)
    return None


def _parse_time(system: dict[str, Any]) -> datetime:
    tc = system.get("TimeCreated")
    if isinstance(tc, dict):
        tc = tc.get("#attributes", {}).get("SystemTime") or tc.get("SystemTime")
    if tc:
        try:
            return datetime.fromisoformat(str(tc).replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime.now(UTC)


class EvtxNormalizer:
    source_type = "evtx"

    def normalize(self, payload: dict[str, Any]) -> NormalizedEventData:
        # payload is one parsed record: {"Event": {"System": {...},
        # "EventData": {...}}} or already-flattened variants.
        event = payload.get("Event", payload)
        system = event.get("System", {}) or {}
        data = event.get("EventData", {}) or {}
        # EventData sometimes parses as {"Data": [{"@Name":..,"#text":..}]}
        if isinstance(data.get("Data"), list):
            flat: dict[str, Any] = {}
            for item in data["Data"]:
                if isinstance(item, dict):
                    name = item.get("@Name") or item.get("Name")
                    val = item.get("#text") or item.get("text")
                    if name:
                        flat[name] = val
            data = flat or data

        event_id = system.get("EventID")
        if isinstance(event_id, dict):
            event_id = event_id.get("#text") or event_id.get("text")
        channel = system.get("Channel") or "windows"
        computer = system.get("Computer")

        attributes: dict[str, Any] = {}
        if event_id is not None:
            attributes["event_id"] = event_id
        attributes["channel"] = channel
        for src, dst in (
            ("Image", "process_image"),
            ("ParentImage", "parent_image"),
            ("TargetImage", "target_image"),
            ("CommandLine", "command_line"),
            ("TargetFilename", "target_filename"),
        ):
            if data.get(src):
                attributes[dst] = data[src]

        return NormalizedEventData(
            event_time=_parse_time(system),
            category=str(channel),
            action=_get(data, "RuleName", "Description") or f"EventID {event_id}",
            severity=None,
            host_name=computer or _get(data, "Computer"),
            user_name=_get(data, "TargetUserName", "SubjectUserName", "User"),
            src_ip=_get(data, "SourceIp", "IpAddress"),
            dst_ip=_get(data, "DestinationIp"),
            attributes=attributes,
        )
