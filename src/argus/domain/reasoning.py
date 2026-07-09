"""Domain contract for LLM reasoning providers.

Same seam as connectors/enrichers/embedders: ARGUS depends on this
Protocol, never a concrete model. Ollama (local, default) and an Anthropic
provider (drop-in, optional) implement it. The reasoning agent passes
CURATED EVIDENCE ONLY (ADR 0010) — never raw logs — to whichever provider.
"""

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class ReasoningRequest:
    system: str
    prompt: str
    max_tokens: int = 1200
    temperature: float = 0.2  # low: analysis should be stable, not creative


@dataclass(frozen=True)
class ReasoningResponse:
    text: str
    provider: str
    model: str


class ReasoningProvider(Protocol):
    name: str

    async def complete(self, req: ReasoningRequest) -> ReasoningResponse:
        ...
