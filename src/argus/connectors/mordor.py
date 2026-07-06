"""Security Datasets (Mordor/OTRF) normalizer — ARGUS connector #2.

Handles the flattened Windows event JSON used by OTRF Security Datasets
(pre-recorded telemetry from executed attack techniques, incl. APT29).
Field names vary by channel; everything here is defensive .get() mapping.
"""

from datetime import UTC, datetime
from typing import Any

from argus.domain.events import NormalizedEventData


def _parse_time(payload: dict[str, Any]) -> datetime:
    for key in ("@timestamp", "EventTime", "TimeCreated"):
        value = payload.get(key)
        if not value:
            continue
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            continue
    return datetime.now(UTC)


class MordorNormalizer:
    source_type = "securitydatasets"

    def normalize(self, payload: dict[str, Any]) -> NormalizedEventData:
        event_id = payload.get("EventID") or payload.get("EventId")
        message = payload.get("Message") or ""
        action = message.split("\n")[0].split("\r")[0][:200] or (
            f"EventID {event_id}" if event_id is not None else "windows event"
        )

        attributes: dict[str, Any] = {}
        for key, attr in (
            ("EventID", "event_id"),
            ("SourceName", "provider"),
            ("Channel", "channel"),
            ("Image", "process_image"),
            ("CommandLine", "command_line"),
            ("ParentImage", "parent_image"),
            ("TargetImage", "target_image"),
            ("TargetFilename", "target_filename"),
            ("Details", "details"),
        ):
            if payload.get(key) is not None:
                attributes[attr] = payload[key]

        # Sysmon often carries the decisive indicator (e.g. the accessed
        # process) only in the Message body. Keep it available to the rule
        # classifier without bloating storage: cap length.
        if payload.get("Message"):
            attributes["message_excerpt"] = str(payload["Message"])[:500]

        return NormalizedEventData(
            event_time=_parse_time(payload),
            category=payload.get("Channel") or payload.get("SourceName") or "windows",
            action=action,
            severity=None,  # datasets carry no alert level; scoring comes later
            host_name=payload.get("Hostname") or payload.get("Computer"),
            user_name=payload.get("User") or payload.get("TargetUserName"),
            src_ip=payload.get("SourceIp") or payload.get("IpAddress"),
            dst_ip=payload.get("DestinationIp"),
            attributes=attributes,
        )
