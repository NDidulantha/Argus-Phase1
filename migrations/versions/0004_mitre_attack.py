"""mitre_techniques (global) + event_techniques (tenant, RLS)

Revision ID: 0004
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "mitre_techniques",
        sa.Column("technique_id", sa.Text(), primary_key=True),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column(
            "tactics", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")
        ),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("parent_id", sa.Text(), nullable=True),
        sa.Column("is_subtechnique", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("url", sa.Text(), nullable=True),
    )

    op.create_table(
        "event_techniques",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "normalized_event_id",
            sa.BigInteger(),
            sa.ForeignKey("normalized_events.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("technique_id", sa.Text(), nullable=False),
        sa.Column("event_time", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.UniqueConstraint("normalized_event_id", "technique_id", name="uq_event_technique"),
    )
    op.create_index(
        "ix_event_techniques_tenant_technique",
        "event_techniques",
        ["tenant_id", "technique_id"],
    )

    op.execute("ALTER TABLE event_techniques ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE event_techniques FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON event_techniques "
        "USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid) "
        "WITH CHECK "
        "(tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)"
    )


def downgrade() -> None:
    op.drop_table("event_techniques")
    op.drop_table("mitre_techniques")
