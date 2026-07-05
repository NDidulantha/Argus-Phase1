"""Wazuh alert normalizer — ARGUS connector #1.

Maps the Wazuh alert JSON shape (rule/agent/data blocks) into
NormalizedEventData. Reference: alerts as delivered by Wazuh integrations
(the same shape Nimsara's wazuh-virustotal lab emits via webhook).
"""

from datetime import UTC, datetime
from typing import Any

from argus.domain.events import NormalizedEventData


def _parse_time(value: str | None) -> datetime:
    if value:
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            pass
    return datetime.now(UTC)  # fall back to receipt time, never fail ingestion


class WazuhNormalizer:
    source_type = "wazuh"

    def normalize(self, payload: dict[str, Any]) -> NormalizedEventData:
        rule = payload.get("rule", {})
        agent = payload.get("agent", {})
        data = payload.get("data", {})
        groups = rule.get("groups") or ["alert"]

        attributes: dict[str, Any] = {"rule_id": rule.get("id")}
        mitre = rule.get("mitre", {})
        if mitre.get("id"):
            attributes["mitre_technique_ids"] = mitre["id"]
        if payload.get("location"):
            attributes["location"] = payload["location"]

        return NormalizedEventData(
            event_time=_parse_time(payload.get("timestamp")),
            category=groups[0],
            action=rule.get("description"),
            severity=rule.get("level"),
            host_name=agent.get("name"),
            user_name=data.get("dstuser") or data.get("srcuser"),
            src_ip=data.get("srcip"),
            dst_ip=data.get("dstip"),
            attributes=attributes,
        )
