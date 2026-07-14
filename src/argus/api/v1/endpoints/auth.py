"""Login and identity endpoints."""

from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from argus.api.deps import CurrentUser, get_current_user
from argus.api.v1.schemas import LoginRequest, MeOut, TokenOut
from argus.core.security import DUMMY_HASH, create_access_token, hash_password, verify_password
from argus.infrastructure.db.models import Tenant, User
from argus.infrastructure.db.session import admin_session, tenant_session

log = structlog.get_logger()
router = APIRouter(prefix="/auth", tags=["auth"])

_INVALID = HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
# One generic message for unknown tenant / unknown user / wrong password:
# never tell an attacker which part was right.


@router.post("/login", response_model=TokenOut)
async def login(body: LoginRequest) -> TokenOut:
    async with admin_session() as s:  # tenants = control-plane, not under RLS
        tenant = await s.scalar(
            select(Tenant).where(Tenant.slug == body.tenant_slug, Tenant.is_active.is_(True))
        )
    if tenant is None:
        verify_password(DUMMY_HASH, body.password)  # burn same time as a real check
        raise _INVALID

    async with tenant_session(tenant.id) as s:
        user = await s.scalar(
            select(User).where(User.email == body.email.lower(), User.is_active.is_(True))
        )

    if user is None:
        verify_password(DUMMY_HASH, body.password)
        raise _INVALID
    if not verify_password(user.password_hash, body.password):
        log.warning("login_failed", tenant=body.tenant_slug, email=body.email)
        raise _INVALID

    return TokenOut(
        access_token=create_access_token(
            user_id=user.id, tenant_id=tenant.id, role=user.role
        )
    )


@router.get("/me", response_model=MeOut)
async def me(current: Annotated[CurrentUser, Depends(get_current_user)]) -> MeOut:
    return MeOut(user_id=current.user_id, tenant_id=current.tenant_id, role=current.role)


class PasswordChangeIn(BaseModel):
    current_password: str
    new_password: str = Field(min_length=10, max_length=200)


@router.post("/password", status_code=204)
async def change_password(
    body: PasswordChangeIn,
    current: Annotated[CurrentUser, Depends(get_current_user)],
) -> None:
    async with tenant_session(current.tenant_id) as s:
        user = await s.get(User, current.user_id)
        if user is None or not verify_password(user.password_hash, body.current_password):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Current password didn't match")
        user.password_hash = hash_password(body.new_password)
        log.info("password_changed", user_id=str(current.user_id))
