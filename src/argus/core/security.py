"""Password hashing (argon2id) and JWT access tokens.

argon2id is the current OWASP-recommended password hash (memory-hard,
GPU-resistant). JWTs are stateless: every request carries tenant_id and
role, which the API layer converts into an RLS-scoped tenant_session.
"""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

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
