"""Login and identity endpoints."""

from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from argus.api.deps import CurrentUser, get_current_user
from argus.api.v1.schemas import LoginRequest, MeOut, TokenOut
from argus.core.security import (
    DUMMY_HASH,
    create_access_token,
    generate_totp_secret,
    hash_password,
    otpauth_uri,
    verify_password,
    verify_totp,
)
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

    # Second factor — only ever surfaced AFTER the password checked out, so
    # "mfa_required" leaks nothing to a guesser.
    if user.mfa_enabled:
        if body.otp_code is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "mfa_required")
        if not verify_totp(user.mfa_secret or "", body.otp_code):
            log.warning("login_mfa_failed", tenant=body.tenant_slug, email=body.email)
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


# --- TOTP MFA management (all require a valid session) ---


class MfaStatusOut(BaseModel):
    enabled: bool
    pending: bool  # secret enrolled but not yet activated


class MfaEnrolOut(BaseModel):
    secret: str
    otpauth_uri: str


class MfaCodeIn(BaseModel):
    code: str = Field(min_length=6, max_length=8)


@router.get("/mfa", response_model=MfaStatusOut)
async def mfa_status(
    current: Annotated[CurrentUser, Depends(get_current_user)],
) -> MfaStatusOut:
    async with tenant_session(current.tenant_id) as s:
        user = await s.get(User, current.user_id)
        if user is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unknown user")
        return MfaStatusOut(
            enabled=user.mfa_enabled,
            pending=bool(user.mfa_secret) and not user.mfa_enabled,
        )


@router.post("/mfa/enrol", response_model=MfaEnrolOut)
async def mfa_enrol(
    current: Annotated[CurrentUser, Depends(get_current_user)],
) -> MfaEnrolOut:
    """Generate (or regenerate) a TOTP secret. MFA only turns on once the
    first code is verified via /mfa/activate — a lost QR can't lock you out."""
    async with tenant_session(current.tenant_id) as s:
        user = await s.get(User, current.user_id)
        if user is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unknown user")
        if user.mfa_enabled:
            raise HTTPException(status.HTTP_409_CONFLICT, "MFA is already enabled")
        user.mfa_secret = generate_totp_secret()
        secret = user.mfa_secret
        email = user.email
    async with admin_session() as s:
        slug = await s.scalar(select(Tenant.slug).where(Tenant.id == current.tenant_id))
    return MfaEnrolOut(
        secret=secret,
        otpauth_uri=otpauth_uri(email=email, tenant_slug=slug or "argus", secret=secret),
    )


@router.post("/mfa/activate", status_code=204)
async def mfa_activate(
    body: MfaCodeIn,
    current: Annotated[CurrentUser, Depends(get_current_user)],
) -> None:
    async with tenant_session(current.tenant_id) as s:
        user = await s.get(User, current.user_id)
        if user is None or not user.mfa_secret:
            raise HTTPException(status.HTTP_409_CONFLICT, "Enrol first")
        if not verify_totp(user.mfa_secret, body.code):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "That code didn't match")
        user.mfa_enabled = True
        log.info("mfa_enabled", user_id=str(current.user_id))


@router.post("/mfa/disable", status_code=204)
async def mfa_disable(
    body: MfaCodeIn,
    current: Annotated[CurrentUser, Depends(get_current_user)],
) -> None:
    """Turning MFA off requires a current code — a hijacked session alone
    can't silently weaken the account."""
    async with tenant_session(current.tenant_id) as s:
        user = await s.get(User, current.user_id)
        if user is None or not user.mfa_enabled:
            raise HTTPException(status.HTTP_409_CONFLICT, "MFA is not enabled")
        if not verify_totp(user.mfa_secret or "", body.code):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "That code didn't match")
        user.mfa_enabled = False
        user.mfa_secret = None
        log.info("mfa_disabled", user_id=str(current.user_id))


# --- Self-service ingest tokens (long-lived machine JWTs for collectors) ---


class IngestTokenIn(BaseModel):
    days: int = Field(default=90, ge=1, le=365)


class IngestTokenOut(BaseModel):
    token: str
    expires_days: int
    role: str = "analyst"


@router.post("/ingest-token", response_model=IngestTokenOut)
async def mint_ingest_token(
    body: IngestTokenIn,
    current: Annotated[CurrentUser, Depends(get_current_user)],
) -> IngestTokenOut:
    """Mint a long-lived token for a collector. Scoped to this tenant and
    pinned to the analyst role regardless of who mints it — a leaked
    collector token must never carry admin rights. Replaces the server-side
    scripts/mint_ingest_token.py for day-to-day use."""
    log.info(
        "ingest_token_minted", user_id=str(current.user_id), days=body.days
    )
    return IngestTokenOut(
        token=create_access_token(
            user_id=current.user_id,
            tenant_id=current.tenant_id,
            role="analyst",
            expires_minutes=body.days * 24 * 60,
        ),
        expires_days=body.days,
    )
