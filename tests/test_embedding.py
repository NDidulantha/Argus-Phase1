"""Unit tests: the hashing embedder."""

import math

from argus.services.embedding import HashingEmbedder


def test_deterministic_and_normalized():
    e = HashingEmbedder()
    a = e.embed("host WS5 T1003 credential-access")
    b = e.embed("host WS5 T1003 credential-access")
    assert a == b  # deterministic
    assert len(a) == 384
    assert abs(math.sqrt(sum(x * x for x in a)) - 1.0) < 1e-6  # L2 normalized


def test_similar_texts_closer_than_dissimilar():
    e = HashingEmbedder()

    def cos(x, y):
        return sum(a * b for a, b in zip(x, y, strict=True))

    cred1 = e.embed("credential-access T1003.001 lsass powershell")
    cred2 = e.embed("credential-access T1003.001 lsass mimikatz")
    discovery = e.embed("discovery T1087 net localgroup enumerate")
    assert cos(cred1, cred2) > cos(cred1, discovery)  # shared vocab = closer
