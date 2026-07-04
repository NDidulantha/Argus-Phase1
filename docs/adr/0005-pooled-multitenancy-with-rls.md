# ADR 0005: Pooled multi-tenancy enforced by Postgres Row-Level Security

Status: Accepted (2026-07-04)

## Context
ARGUS serves multiple MSSP customers (banking, healthcare, insurance) from
one platform. Isolation options: pooled (shared schema + tenant_id),
schema-per-tenant, database-per-tenant. Pooled enables cross-tenant threat
hunting and lowest operational cost, but a single missing WHERE clause
could leak data between regulated customers.

## Decision
Pooled model: every tenant-owned table carries tenant_id. Isolation is
enforced in TWO layers:
1. Application: sessions are tenant-scoped (`tenant_session`).
2. Database: RLS policies (ENABLE + FORCE) with USING and WITH CHECK on
   tenant_id = current_setting('app.current_tenant'). Unset context =>
   default deny. The setting is applied with set_config(..., local=true),
   so it is transaction-scoped and cannot leak across pooled connections.

## Consequences
+ A forgotten filter returns zero rows instead of another tenant's rows.
+ Cross-tenant writes are rejected by Postgres itself (WITH CHECK).
+ Strong story for audits and security-sensitive customers.
- Every data-plane query must run inside a tenant_session.
- Production hardening (later): separate migration role (table owner) from
  runtime app role (non-owner, no BYPASSRLS).
- Integration tests (tests/integration/test_tenant_isolation.py) are the
  executable proof of this ADR and must never be skipped in CI.

## Amendment (2026-07-04): app role must never be a superuser
Incident: with the pgvector Docker image, POSTGRES_USER creates a
SUPERUSER, and superusers bypass RLS unconditionally (FORCE does not
apply to them). Policies existed but were ignored; cross-tenant reads
succeeded in dev.

Fix: compose now bootstraps as `postgres` and an init script
(db/init/01-create-app-role.sql) creates the runtime role with
NOSUPERUSER NOBYPASSRLS. CI provisions the same. A regression test
(test_app_role_cannot_bypass_rls) fails the suite if the connected role
could ever bypass RLS.
