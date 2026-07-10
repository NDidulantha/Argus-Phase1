"""Domain contract for CTI (Cyber Threat Intelligence) providers.

Distinct from the enrichment layer (score/verdict). CTI providers answer
the deeper questions with CITED FACTS: has this been seen before, when,
where, what malware/actor, is this CVE exploited — each with a source
reference. If a provider has nothing, it returns an empty result: a
truthful 'no external intel' beats a guess (the whole point).
"""

from dataclasses import dataclass, field
from typing import Any, Protocol

# indicator kinds a CTI provider may accept
CTI_INDICATOR_TYPES = ("ip", "domain", "url", "hash", "cve")


@dataclass(frozen=True)
class CTIFinding:
    """One cited fact from one provider about one indicator."""

    provider: str
    indicator_type: str
    indicator_value: str
    found: bool
    malware: list[str] = field(default_factory=list)
    threat_actors: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    confidence: int | None = None  # provider-reported, 0-100 where available
    reference_url: str | None = None  # CITATION — where an analyst can verify
    summary: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


class CTIProvider(Protocol):
    provider: str
    supported_types: frozenset[str]

    async def lookup(self, indicator_type: str, value: str) -> CTIFinding:
        """Query the source. Must not raise for 'not found' — return
        found=False. May raise on transport errors; the service degrades."""
        ...
