"""Connector-credential encryption at rest (Fernet: AES-128-CBC + HMAC).

Credentials live in a JSONB column; encrypted rows hold a single
{"__fernet__": "<token>"} marker instead of the plaintext dict. Reads
accept both shapes, so rows written before encryption keep working and
get sealed the next time they are saved (migration 0014 seals the
backlog in one pass).
"""

import base64
import hashlib
import json
from functools import lru_cache
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from argus.core.config import get_settings

_MARKER = "__fernet__"


@lru_cache
def _fernet() -> Fernet:
    settings = get_settings()
    if settings.credentials_key:
        return Fernet(settings.credentials_key)
    # Dev fallback: derive a stable key from the JWT secret so a fresh
    # checkout works. Production sets ARGUS_CREDENTIALS_KEY explicitly
    # (Fernet.generate_key()) so credential and session secrets rotate
    # independently.
    derived = hashlib.sha256(f"argus-credentials:{settings.jwt_secret}".encode()).digest()
    return Fernet(base64.urlsafe_b64encode(derived))


def encrypt_credentials(credentials: dict[str, Any]) -> dict[str, str]:
    token = _fernet().encrypt(json.dumps(credentials).encode())
    return {_MARKER: token.decode()}


def decrypt_credentials(stored: dict[str, Any]) -> dict[str, Any]:
    """Return the plaintext credentials dict; legacy plaintext rows pass
    through untouched. Raises InvalidToken if the key doesn't match."""
    if _MARKER not in stored:
        return stored
    return json.loads(_fernet().decrypt(stored[_MARKER].encode()))


def is_encrypted(stored: dict[str, Any]) -> bool:
    return _MARKER in stored


__all__ = [
    "InvalidToken",
    "decrypt_credentials",
    "encrypt_credentials",
    "is_encrypted",
]
