"""Request/response models. Pydantic validates every byte entering the API."""

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


class TenantCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    slug: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9-]+$")


class TenantOut(BaseModel):
    id: uuid.UUID
    name: str
    slug: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    role: str = Field(default="analyst", pattern=r"^(analyst|admin)$")


class UserOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    email: EmailStr
    role: str

    model_config = {"from_attributes": True}


class LoginRequest(BaseModel):
    tenant_slug: str
    email: EmailStr
    password: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class MeOut(BaseModel):
    user_id: uuid.UUID
    tenant_id: uuid.UUID
    role: str
