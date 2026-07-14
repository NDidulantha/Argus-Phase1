"""connectors: per-tenant SIEM/XDR data-source configs (tenant, RLS)

Revision ID: 0011
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None

_RLS = (
    "USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid) "
    "WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)"
)


def upgrade() -> None:
    op.create_table(
        "connectors",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("vendor", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("endpoint_url", sa.Text(), nullable=False),
        sa.Column(
            "credentials",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("verify_tls", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column(
            "field_mapping",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("status", sa.Text(), nullable=False, server_default=sa.text("'unconfigured'")),
        sa.Column("last_checked_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index("ix_connectors_tenant", "connectors", ["tenant_id"])
    op.execute("ALTER TABLE connectors ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE connectors FORCE ROW LEVEL SECURITY")
    op.execute(f"CREATE POLICY tenant_isolation ON connectors {_RLS}")


def downgrade() -> None:
    op.drop_table("connectors")
