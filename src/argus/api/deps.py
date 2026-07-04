"""FastAPI dependencies: the bridge from HTTP auth to RLS-scoped data access."""

import secrets
import uuid
from dataclasses import dataclass
from typing import Annotated

import jwt
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from argus.core.config import get_settings
from argus.core.security import decode_access_token

_bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class CurrentUser:
    user_id: uuid.UUID
    tenant_id: uuid.UUID
    role: str


async def get_current_user(
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> CurrentUser:
    if creds is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing bearer token")
    try:
        claims = decode_access_token(creds.credentials)
        return CurrentUser(
            user_id=uuid.UUID(claims["sub"]),
            tenant_id=uuid.UUID(claims["tid"]),
            role=claims["role"],
        )
    except (jwt.InvalidTokenError, KeyError, ValueError):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token") from None


async def require_admin_key(x_admin_key: Annotated[str | None, Header()] = None) -> None:
    """Platform-operator endpoints (tenant provisioning). Solves the
    bootstrap problem: someone must create the first tenant/user before any
    JWT can exist. compare_digest = constant-time, no timing leak."""
    expected = get_settings().admin_api_key
    if x_admin_key is None or not secrets.compare_digest(x_admin_key, expected):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid admin key")
