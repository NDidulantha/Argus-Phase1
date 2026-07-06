"""SQLAlchemy ORM models.

Every tenant-owned table carries tenant_id and is protected by Postgres
Row-Level Security (see migration 0001). `tenants` itself is control-plane
data managed by the platform operator and is NOT under RLS.

ID strategy:
- tenants/users: UUID (safe to expose externally, no enumeration).
- raw_events/normalized_events: BIGINT identity (high-volume append tables;
  sequential ints keep the B-tree index compact, and event ids are never
  exposed as external references).
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    ForeignKey,
    Identity,
    SmallInteger,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, TIMESTAMP, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    name: Mapped[str] = mapped_column(Text, unique=True)
    slug: Mapped[str] = mapped_column(Text, unique=True)
    is_active: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=text("now()")
    )


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("tenant_id", "email", name="uq_users_tenant_email"),)

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE")
    )
    email: Mapped[str] = mapped_column(Text)
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(Text, server_default=text("'analyst'"))
    is_active: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=text("now()")
    )


class RawEvent(Base):
    __tablename__ = "raw_events"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE")
    )
    source: Mapped[str] = mapped_column(Text)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    received_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=text("now()")
    )


class NormalizedEvent(Base):
    __tablename__ = "normalized_events"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE")
    )
    raw_event_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("raw_events.id", ondelete="SET NULL"), nullable=True
    )
    event_time: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True))
    category: Mapped[str] = mapped_column(Text)
    action: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    host_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    user_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    src_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    attributes: Mapped[dict[str, Any]] = mapped_column(
        JSONB, server_default=text("'{}'::jsonb")
    )
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=text("now()")
    )


class EventAggregate(Base):
    """Rollup of repeated normalized events sharing a signature.

    Signature = category + host + stable rule key (rule_id/event_id), so
    thousands of near-identical events collapse into one row with a count
    and first/last-seen. Downstream stages (and analysts) reason over
    signals, not repetition. `is_open` supports future window-closing.
    """

    __tablename__ = "event_aggregates"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE")
    )
    signature_hash: Mapped[str] = mapped_column(Text)
    category: Mapped[str] = mapped_column(Text)
    action: Mapped[str | None] = mapped_column(Text, nullable=True)  # sample
    host_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity_max: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    count: Mapped[int] = mapped_column(BigInteger, server_default=text("1"))
    first_seen: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True))
    sample_normalized_event_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("normalized_events.id", ondelete="SET NULL"), nullable=True
    )
    is_open: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))


class EnrichmentCache(Base):
    """Cached threat-intel verdicts. GLOBAL table (no tenant_id, no RLS):
    indicator reputation is world knowledge, not tenant data. Sharing it
    means one provider lookup serves every tenant — and protects API
    quotas, which free-tier intel providers enforce aggressively."""

    __tablename__ = "enrichment_cache"
    __table_args__ = (
        UniqueConstraint(
            "provider", "indicator_type", "indicator_value", name="uq_enrichment_indicator"
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    provider: Mapped[str] = mapped_column(Text)
    indicator_type: Mapped[str] = mapped_column(Text)
    indicator_value: Mapped[str] = mapped_column(Text)
    score: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    verdict: Mapped[str] = mapped_column(Text, server_default=text("'unknown'"))
    raw: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    fetched_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=text("now()")
    )


class MitreTechnique(Base):
    """ATT&CK technique catalog. GLOBAL reference data (no tenant_id/RLS).
    Sub-techniques (T1110.001) carry parent_id -> T1110."""

    __tablename__ = "mitre_techniques"

    technique_id: Mapped[str] = mapped_column(Text, primary_key=True)  # e.g. T1110
    name: Mapped[str] = mapped_column(Text)
    tactics: Mapped[list] = mapped_column(JSONB, server_default=text("'[]'::jsonb"))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    parent_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_subtechnique: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    url: Mapped[str | None] = mapped_column(Text, nullable=True)


class EventTechnique(Base):
    """Per-tenant link: a normalized event maps to an ATT&CK technique.
    Tenant-owned -> RLS. Makes the bare 'T1110' strings first-class."""

    __tablename__ = "event_techniques"
    __table_args__ = (
        UniqueConstraint("normalized_event_id", "technique_id", name="uq_event_technique"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE")
    )
    normalized_event_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("normalized_events.id", ondelete="CASCADE")
    )
    technique_id: Mapped[str] = mapped_column(Text)
    event_time: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True))
    # Provenance of this mapping: vendor (upstream supplied), rules
    # (deterministic classifier), or ai (Phase 3 inference). Auditable
    # answer to "why does ARGUS think this event is T1003?".
    mapping_source: Mapped[str] = mapped_column(Text, server_default=text("'vendor'"))
    confidence: Mapped[int] = mapped_column(SmallInteger, server_default=text("100"))
