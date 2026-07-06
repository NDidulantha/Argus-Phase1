"""Domain contract for threat-intelligence enrichment.

Same seam pattern as EventNormalizer: each intel provider (VirusTotal,
AbuseIPDB, OTX, future commercial feeds) implements one protocol; the
platform core never imports provider code.
"""

from dataclasses import dataclass, field
from typing import Any, Protocol

INDICATOR_TYPES = ("ip", "domain", "hash")


@dataclass(frozen=True)
class EnrichmentResult:
    provider: str
    indicator_type: str
    indicator_value: str
    score: int | None  # normalized 0-100 (None = provider gave no signal)
    verdict: str  # malicious | suspicious | clean | unknown
    raw: dict[str, Any] = field(default_factory=dict)


class Enricher(Protocol):
    provider: str
    supported_types: frozenset[str]

    async def enrich(self, indicator_type: str, value: str) -> EnrichmentResult:
        """Query the provider. May raise on HTTP/parse errors; the service
        treats that as 'no result from this provider', never a failure."""
        ...
