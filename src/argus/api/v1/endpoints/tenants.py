"""Platform-operator endpoints (X-Admin-Key protected): tenant provisioning."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from argus.api.deps import require_admin_key
from argus.api.v1.schemas import TenantCreate, TenantOut, UserCreate, UserOut
from argus.core.security import hash_password
from argus.infrastructure.db.models import Tenant, User
from argus.infrastructure.db.session import admin_session, tenant_session

router = APIRouter(
    prefix="/admin/tenants", tags=["admin"], dependencies=[Depends(require_admin_key)]
)


@router.post("", response_model=TenantOut, status_code=status.HTTP_201_CREATED)
async def create_tenant(body: TenantCreate) -> Tenant:
    try:
        async with admin_session() as s:
            tenant = Tenant(name=body.name, slug=body.slug)
            s.add(tenant)
            await s.flush()
            await s.refresh(tenant)
            return tenant
    except IntegrityError:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Tenant name or slug already exists"
        ) from None


@router.post("/{tenant_id}/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(tenant_id: uuid.UUID, body: UserCreate) -> User:
    async with admin_session() as s:
        if await s.scalar(select(Tenant.id).where(Tenant.id == tenant_id)) is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Tenant not found")
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
