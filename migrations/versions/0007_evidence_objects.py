"""evidence_objects: correlated, scored activity clusters (tenant, RLS)

Revision ID: 0007
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None

_RLS = (
    "USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid) "
    "WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)"
)


def upgrade() -> None:
    op.create_table(
        "evidence_objects",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("host_name", sa.Text(), nullable=True),
        sa.Column("window_start", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("window_end", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("event_count", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
        sa.Column(
            "technique_ids",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "tactics", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")
        ),
        sa.Column(
            "entity_ids", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")
        ),
        sa.Column("score", sa.SmallInteger(), nullable=False, server_default=sa.text("0")),
        sa.Column(
            "score_breakdown",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("status", sa.Text(), nullable=False, server_default=sa.text("'open'")),
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
    op.create_index("ix_evidence_tenant_score", "evidence_objects", ["tenant_id", "score"])
    op.execute("ALTER TABLE evidence_objects ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE evidence_objects FORCE ROW LEVEL SECURITY")
    op.execute(f"CREATE POLICY tenant_isolation ON evidence_objects {_RLS}")


def downgrade() -> None:
    op.drop_table("evidence_objects")
