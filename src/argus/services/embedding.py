"""Embedding providers + registry.

Default: HashingEmbedder — a deterministic, dependency-free bag-of-features
hashing vectorizer. It is NOT semantically deep, but it is fast, offline,
reproducible, and good enough to cluster/retrieve similar evidence objects
by their technique/tactic/host vocabulary. It exists so the RAG pipeline
and reasoning agent can be built and tested end-to-end today.

To upgrade to real semantic embeddings, implement an Embedder that wraps
sentence-transformers (runs on Nimsara's RTX 5050) or an API, register it,
and set ARGUS_EMBEDDING_PROVIDER — no caller changes. Re-embed existing
rows via a backfill (evidence text is retained).
"""

import hashlib
import math
import re

from argus.core.config import get_settings
from argus.domain.embedding import EMBEDDING_DIM, Embedder

_TOKEN_RE = re.compile(r"[a-z0-9_.:-]+")


class HashingEmbedder:
    provider = "hashing-v1"
    dim = EMBEDDING_DIM

    def embed(self, text: str) -> list[float]:
        vec = [0.0] * self.dim
        tokens = _TOKEN_RE.findall(text.lower())
        for tok in tokens:
            h = int(hashlib.md5(tok.encode()).hexdigest(), 16)  # noqa: S324 - non-crypto use
            idx = h % self.dim
            sign = 1.0 if (h >> 8) & 1 else -1.0
            vec[idx] += sign
        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        return [v / norm for v in vec]  # L2-normalized -> cosine == dot


_EMBEDDERS: dict[str, Embedder] = {
    HashingEmbedder.provider: HashingEmbedder(),
}


def get_embedder() -> Embedder:
    name = get_settings().embedding_provider
    return _EMBEDDERS.get(name, _EMBEDDERS["hashing-v1"])
