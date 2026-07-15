"""Platform-operator endpoints (X-Admin-Key protected): tenant provisioning
and the MSSP control plane — list tenants with usage stats, edit/deactivate
tenants, manage each tenant's users."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from argus.api.deps import require_admin_key
from argus.api.v1.schemas import (
    TenantAdminOut,
    TenantCreate,
    TenantOut,
    TenantUpdate,
    UserAdminOut,
    UserCreate,
    UserOut,
    UserUpdate,
)
from argus.core.security import hash_password
from argus.infrastructure.db.models import EvidenceObject, NormalizedEvent, Tenant, User
from argus.infrastructure.db.session import admin_session, tenant_session

router = APIRouter(
    prefix="/admin/tenants", tags=["admin"], dependencies=[Depends(require_admin_key)]
)


@router.get("", response_model=list[TenantAdminOut])
async def list_tenants() -> list[TenantAdminOut]:
    """All tenants with usage stats. Stats are read through a tenant-scoped
    session per tenant: the RLS path is the only read path, even for the
    operator (ADR 0005)."""
    async with admin_session() as s:
        tenants = (await s.scalars(select(Tenant).order_by(Tenant.created_at))).all()
        base = [TenantOut.model_validate(t).model_dump() for t in tenants]

    out = []
    for row in base:
        async with tenant_session(row["id"]) as s:
            user_count = await s.scalar(select(func.count(User.id))) or 0
            event_count = await s.scalar(select(func.count(NormalizedEvent.id))) or 0
            open_alerts = (
                await s.scalar(
                    select(func.count(EvidenceObject.id)).where(
                        EvidenceObject.status == "open"
                    )
                )
                or 0
            )
        out.append(
            TenantAdminOut(
                **row,
                user_count=user_count,
                event_count=event_count,
                open_alerts=open_alerts,
            )
        )
    return out


@router.post("", response_model=TenantOut, status_code=status.HTTP_201_CREATED)
async def create_tenant(body: TenantCreate) -> Tenant:
    try:
        async with admin_session() as s:
            tenant = Tenant(name=body.name, slug=body.slug, sector=body.sector)
            s.add(tenant)
            await s.flush()
            await s.refresh(tenant)
            return tenant
    except IntegrityError:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Tenant name or slug already exists"
        ) from None


@router.patch("/{tenant_id}", response_model=TenantOut)
async def update_tenant(tenant_id: uuid.UUID, body: TenantUpdate) -> Tenant:
    """Rename, relabel or (de)activate a tenant. Deactivation locks out
    logins immediately; the slug is permanent (it is the login identifier)."""
    try:
        async with admin_session() as s:
            tenant = await s.get(Tenant, tenant_id)
            if tenant is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "Tenant not found")
            for field, value in body.model_dump(exclude_unset=True).items():
                setattr(tenant, field, value)
            await s.flush()
            await s.refresh(tenant)
            return tenant
    except IntegrityError:
        raise HTTPException(status.HTTP_409_CONFLICT, "Tenant name already exists") from None


async def _require_tenant(tenant_id: uuid.UUID) -> None:
    async with admin_session() as s:
        if await s.scalar(select(Tenant.id).where(Tenant.id == tenant_id)) is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Tenant not found")


@router.get("/{tenant_id}/users", response_model=list[UserAdminOut])
async def list_users(tenant_id: uuid.UUID) -> list[UserAdminOut]:
    await _require_tenant(tenant_id)
    async with tenant_session(tenant_id) as s:
        users = (await s.scalars(select(User).order_by(User.created_at))).all()
        return [UserAdminOut.model_validate(u) for u in users]


@router.post("/{tenant_id}/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(tenant_id: uuid.UUID, body: UserCreate) -> User:
    await _require_tenant(tenant_id)
    try:
        # users table is under RLS, so even the operator writes through a
        # tenant-scoped session — the same enforcement path as everything else.
        async with tenant_session(tenant_id) as s:
            user = User(
                tenant_id=tenant_id,
                email=body.email.lower(),
                password_hash=hash_password(body.password),
                role=body.role,
            )
            s.add(user)
            await s.flush()
            await s.refresh(user)
            return user
    except IntegrityError:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "User already exists in this tenant"
        ) from None


@router.patch("/{tenant_id}/users/{user_id}", response_model=UserAdminOut)
async def update_user(tenant_id: uuid.UUID, user_id: uuid.UUID, body: UserUpdate) -> User:
    """Change role, (de)activate, or reset a password for a tenant's user."""
    await _require_tenant(tenant_id)
    async with tenant_session(tenant_id) as s:
        user = await s.get(User, user_id)
        if user is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
        changes = body.model_dump(exclude_unset=True)
        if "password" in changes:
            user.password_hash = hash_password(changes.pop("password"))
        for field, value in changes.items():
            setattr(user, field, value)
        await s.flush()
        await s.refresh(user)
        return user
