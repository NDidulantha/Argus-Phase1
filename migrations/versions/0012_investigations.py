"""investigations: persisted reasoning runs per evidence object (tenant, RLS)

Revision ID: 0012
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None

_RLS = (
    "USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid) "
    "WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)"
)


def upgrade() -> None:
    op.create_table(
        "investigations",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "evidence_id",
            sa.BigInteger(),
            sa.ForeignKey("evidence_objects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.Text(), nullable=False, server_default=sa.text("'running'")),
        sa.Column("provider", sa.Text(), nullable=True),
        sa.Column("model", sa.Text(), nullable=True),
        sa.Column("narrative", sa.Text(), nullable=True),
        sa.Column("grounded", sa.Boolean(), nullable=True),
        sa.Column(
            "unsupported_terms",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "directives",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "stages", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")
        ),
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "started_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("finished_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
    )
    op.create_index(
        "ix_investigations_tenant_evidence", "investigations", ["tenant_id", "evidence_id"]
    )
    op.execute("ALTER TABLE investigations ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE investigations FORCE ROW LEVEL SECURITY")
    op.execute(f"CREATE POLICY tenant_isolation ON investigations {_RLS}")


def downgrade() -> None:
    op.drop_table("investigations")
