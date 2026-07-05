"""Domain contract for event normalization.

This is THE vendor-independence seam in ARGUS. Every security product
(Wazuh, Cortex XDR, FortiSIEM, Trellix, CrowdStrike, Chronicle, QRadar,
Sentinel, ...) speaks its own JSON dialect; a normalizer translates that
dialect into one NormalizedEventData shape the rest of the platform
understands. The core never imports vendor code — only this protocol.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol


@dataclass(frozen=True)
class NormalizedEventData:
    """Vendor-neutral representation of one security event."""

    event_time: datetime
    category: str
    action: str | None = None
    severity: int | None = None
    host_name: str | None = None
    user_name: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)


class EventNormalizer(Protocol):
    """Implemented by each vendor connector."""

    source_type: str

    def normalize(self, payload: dict[str, Any]) -> NormalizedEventData:
        """Translate one raw vendor payload. May raise on malformed input;
        the ingestion service treats that as 'store raw, skip normalized'."""
        ...
