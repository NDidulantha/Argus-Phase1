"""CrowdStrike Falcon alert normalizer — ARGUS connector #4.

Maps a Falcon alert resource (Alerts API v2) into NormalizedEventData.
Falcon already resolves the ATT&CK technique, so we carry technique_id
straight through as mitre_technique_ids (the mitre linker consumes it), and
also surface the process image / command line so the deterministic
classifier can corroborate. Everything is defensive .get() mapping.
"""

from datetime import UTC, datetime
from typing import Any

from argus.domain.events import NormalizedEventData


def _parse_time(value: str | None) -> datetime:
    if value:
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime.now(UTC)  # fall back to receipt time, never fail ingestion


class CrowdStrikeNormalizer:
    source_type = "crowdstrike"

    def normalize(self, payload: dict[str, Any]) -> NormalizedEventData:
        device = payload.get("device") or {}

        attributes: dict[str, Any] = {}
        if payload.get("technique_id"):
            # Falcon resolves ATT&CK for us -> feed the mitre linker directly.
            attributes["mitre_technique_ids"] = [payload["technique_id"]]
        for src, dst in (
            ("tactic", "tactic"),
            ("technique", "technique"),
            ("cmdline", "command_line"),
            ("filename", "process_image"),
            ("filepath", "process_path"),
            ("composite_id", "composite_id"),
            ("severity_name", "severity_name"),
            ("pattern_disposition", "pattern_disposition"),
        ):
            if payload.get(src) is not None:
                attributes[dst] = payload[src]
        if device.get("platform_name"):
            attributes["platform"] = device["platform_name"]

        return NormalizedEventData(
            event_time=_parse_time(payload.get("timestamp") or payload.get("created_timestamp")),
            category=payload.get("tactic") or payload.get("product") or "detection",
            action=payload.get("description") or payload.get("display_name"),
            severity=payload.get("severity"),
            host_name=device.get("hostname"),
            user_name=payload.get("user_name"),
            src_ip=device.get("external_ip") or device.get("local_ip"),
            dst_ip=None,
            attributes=attributes,
        )
