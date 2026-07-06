"""event_aggregates: signature rollups with RLS

Revision ID: 0002
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "event_aggregates",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("signature_hash", sa.Text(), nullable=False),
        sa.Column("category", sa.Text(), nullable=False),
        sa.Column("action", sa.Text(), nullable=True),
        sa.Column("host_name", sa.Text(), nullable=True),
        sa.Column("severity_max", sa.SmallInteger(), nullable=True),
        sa.Column("count", sa.BigInteger(), nullable=False, server_default=sa.text("1")),
        sa.Column("first_seen", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("last_seen", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column(
            "sample_normalized_event_id",
            sa.BigInteger(),
            sa.ForeignKey("normalized_events.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("is_open", sa.Boolean(), nullable=False, server_default=sa.text("true")),
    )
    # ON CONFLICT upsert target: one OPEN aggregate per signature per tenant.
    op.create_index(
        "uq_event_aggregates_open_signature",
        "event_aggregates",
        ["tenant_id", "signature_hash"],
        unique=True,
        postgresql_where=sa.text("is_open"),
    )
    op.create_index(
        "ix_event_aggregates_tenant_count", "event_aggregates", ["tenant_id", "count"]
    )

    # Same RLS treatment as every tenant-owned table (see 0001).
    op.execute("ALTER TABLE event_aggregates ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE event_aggregates FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON event_aggregates "
        "USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid) "
        "WITH CHECK "
        "(tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)"
    )


def downgrade() -> None:
    op.drop_table("event_aggregates")
