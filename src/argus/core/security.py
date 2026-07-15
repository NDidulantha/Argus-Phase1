"""Password hashing (argon2id) and JWT access tokens.

argon2id is the current OWASP-recommended password hash (memory-hard,
GPU-resistant). JWTs are stateless: every request carries tenant_id and
role, which the API layer converts into an RLS-scoped tenant_session.
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError

from argus.core.config import get_settings

_hasher = PasswordHasher()

# Verified when a login targets a nonexistent user, so "unknown user" and
# "wrong password" take the same time (prevents user-enumeration timing).
DUMMY_HASH = PasswordHasher().hash("argus-dummy-password")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except VerificationError:
        return False


def create_access_token(
    *,
    user_id: uuid.UUID,
    tenant_id: uuid.UUID,
    role: str,
    expires_minutes: int | None = None,
) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    minutes = settings.jwt_expiry_minutes if expires_minutes is None else expires_minutes
    claims = {
        "sub": str(user_id),
        "tid": str(tenant_id),
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=minutes),
    }
    return jwt.encode(claims, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict[str, Any]:
    """Raises jwt.InvalidTokenError on bad signature, expiry, or format."""
    settings = get_settings()
    return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])


# --- TOTP (RFC 6238; SHA-1, 30s step, 6 digits — what authenticator apps
# implement). Standard library only: HMAC over a big-endian step counter.


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode()


def _totp_code(secret: str, counter: int) -> str:
    key = base64.b32decode(secret)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{number % 1_000_000:06d}"


def verify_totp(secret: str, code: str, *, at: float | None = None, window: int = 1) -> bool:
    """Accept the current step ± `window` (clock drift). Constant-time
    comparison per candidate step."""
    if not secret or not code:
        return False
    code = code.strip()
    step = int((time.time() if at is None else at) // 30)
    return any(
        hmac.compare_digest(_totp_code(secret, step + offset), code)
        for offset in range(-window, window + 1)
    )


def otpauth_uri(*, email: str, tenant_slug: str, secret: str) -> str:
    """Provisioning URI for authenticator apps (QR or manual entry)."""
    label = quote(f"ARGUS:{tenant_slug}/{email}")
    return f"otpauth://totp/{label}?secret={secret}&issuer=ARGUS"
