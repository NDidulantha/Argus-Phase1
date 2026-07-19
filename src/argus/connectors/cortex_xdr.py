"""Palo Alto Cortex XDR alert normalizer — ARGUS connector #5.

Maps a Cortex XDR alert (get_alerts_multi_events) into NormalizedEventData.
Cortex resolves ATT&CK, so the technique id in mitre_technique_id_and_name
(e.g. "T1055 - Process Injection") flows into mitre_technique_ids for the
linker; the causality actor process image / command line are surfaced so the
deterministic classifier can corroborate. Timestamps are epoch milliseconds.
"""

from datetime import UTC, datetime
from typing import Any

from argus.domain.events import NormalizedEventData

# Cortex severity is a string enum -> a numeric the platform can rank/clamp.
_SEVERITY = {"informational": 0, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _event_time(payload: dict[str, Any]) -> datetime:
    ms = payload.get("detection_timestamp") or payload.get("creation_time")
    if isinstance(ms, (int, float)):
        try:
            return datetime.fromtimestamp(ms / 1000, UTC)
        except (ValueError, OSError, OverflowError):
            pass
    return datetime.now(UTC)  # never fail ingestion on a bad timestamp


def _mitre_ids(value: Any) -> list[str]:
    """Pull T-codes out of "T1055 - Process Injection" (scalar or list)."""
    items = value if isinstance(value, list) else ([value] if value else [])
    ids: list[str] = []
    for it in items:
        token = str(it).split()[0].strip(" -")
        if len(token) >= 2 and token[0] in "Tt" and token[1].isdigit():
            ids.append(token.upper())
    return ids


class CortexXdrNormalizer:
    source_type = "cortex_xdr"

    def normalize(self, payload: dict[str, Any]) -> NormalizedEventData:
        attributes: dict[str, Any] = {}
        mitre = _mitre_ids(payload.get("mitre_technique_id_and_name"))
        if mitre:
            attributes["mitre_technique_ids"] = mitre
        for src, dst in (
            ("alert_id", "alert_id"),
            ("severity", "severity_name"),
            ("mitre_tactic_id_and_name", "tactic"),
            ("causality_actor_process_command_line", "command_line"),
            ("causality_actor_process_image_name", "process_image"),
            ("action_process_image_name", "action_process_image"),
        ):
            if payload.get(src) is not None:
                attributes[dst] = payload[src]

        sev = payload.get("severity")
        severity = _SEVERITY.get(str(sev).lower()) if sev is not None else None

        return NormalizedEventData(
            event_time=_event_time(payload),
            category=payload.get("category") or "alert",
            action=payload.get("description") or payload.get("name"),
            severity=severity,
            host_name=payload.get("host_name") or payload.get("agent_hostname"),
            user_name=payload.get("user_name") or payload.get("actor_effective_username"),
            src_ip=payload.get("action_local_ip") or payload.get("host_ip"),
            dst_ip=payload.get("action_remote_ip"),
            attributes=attributes,
        )
