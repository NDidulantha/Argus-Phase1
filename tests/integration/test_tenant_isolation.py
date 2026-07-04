"""THE most important tests in ARGUS.

They prove, against a real Postgres, that Row-Level Security makes
cross-tenant data access structurally impossible: reads are scoped,
unscoped sessions see nothing (default deny), and cross-tenant writes
are rejected by the database itself.
"""

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from argus.infrastructure.db.models import RawEvent, Tenant
from argus.infrastructure.db.session import admin_session, tenant_session


@pytest.fixture
async def two_tenants(migrated_db):
    async with admin_session() as s:
        bank = Tenant(name="Bank A", slug="bank-a")
        clinic = Tenant(name="Clinic B", slug="clinic-b")
        s.add_all([bank, clinic])
        await s.flush()
        ids = (bank.id, clinic.id)
    yield ids
    # cleanup so the fixture is re-runnable within the session-scoped schema
    async with admin_session() as s:
        for t in await s.scalars(select(Tenant)):
            await s.delete(t)


async def test_tenants_only_see_their_own_events(two_tenants):
    bank_id, clinic_id = two_tenants

    async with tenant_session(bank_id) as s:
        s.add(RawEvent(tenant_id=bank_id, source="wazuh", payload={"alert": "bank"}))
    async with tenant_session(clinic_id) as s:
        s.add(RawEvent(tenant_id=clinic_id, source="cortex_xdr", payload={"alert": "clinic"}))

    async with tenant_session(bank_id) as s:
        rows = (await s.scalars(select(RawEvent))).all()
        assert [r.source for r in rows] == ["wazuh"]

    async with tenant_session(clinic_id) as s:
        rows = (await s.scalars(select(RawEvent))).all()
        assert [r.source for r in rows] == ["cortex_xdr"]


async def test_no_tenant_context_means_default_deny(two_tenants):
    bank_id, _ = two_tenants
    async with tenant_session(bank_id) as s:
        s.add(RawEvent(tenant_id=bank_id, source="wazuh", payload={}))

    async with admin_session() as s:
        rows = (await s.scalars(select(RawEvent))).all()
        assert rows == []  # RLS default deny: unscoped sessions see nothing


async def test_cross_tenant_write_is_rejected_by_the_database(two_tenants):
    bank_id, clinic_id = two_tenants

    with pytest.raises(DBAPIError):  # WITH CHECK violation raised by Postgres
        async with tenant_session(bank_id) as s:
            s.add(RawEvent(tenant_id=clinic_id, source="evil", payload={}))
            await s.flush()


async def test_app_role_cannot_bypass_rls(migrated_db):
    """Regression guard: RLS is worthless if the app connects as a superuser
    or a BYPASSRLS role — policies exist but are silently ignored. This test
    exists because exactly that happened during development (the Docker
    image's bootstrap POSTGRES_USER is a superuser)."""
    async with admin_session() as s:
        row = (
            await s.execute(
                text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
            )
        ).one()
        assert row.rolsuper is False, "app must not connect as a superuser"
        assert row.rolbypassrls is False, "app role must not have BYPASSRLS"
