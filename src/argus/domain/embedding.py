"""Domain contract for embedding providers.

Same seam pattern as connectors/enrichers: the platform depends on this
Protocol, never a concrete model. Swap a deterministic hashing embedder
for sentence-transformers (local GPU) or an API embedder without touching
callers. EMBEDDING_DIM is fixed platform-wide so stored vectors stay
comparable across provider swaps of the same dimension.
"""

from typing import Protocol

EMBEDDING_DIM = 384  # matches all-MiniLM-L6-v2, a common local model


class Embedder(Protocol):
    provider: str
    dim: int

    def embed(self, text: str) -> list[float]:
        ...
