"""cases: analyst investigation cases linking evidence, with notes (tenant, RLS)

Revision ID: 0010
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None

_RLS = (
    "USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid) "
    "WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)"
)


def _tenant_col() -> sa.Column:
    return sa.Column(
        "tenant_id",
        postgresql.UUID(as_uuid=True),
        sa.ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )


def upgrade() -> None:
    op.create_table(
        "cases",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        _tenant_col(),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.Text(), nullable=False, server_default=sa.text("'medium'")),
        sa.Column("status", sa.Text(), nullable=False, server_default=sa.text("'new'")),
        sa.Column(
            "assignee_user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
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
    op.create_index("ix_cases_tenant_status", "cases", ["tenant_id", "status"])

    op.create_table(
        "case_evidence",
        sa.Column(
            "case_id",
            sa.BigInteger(),
            sa.ForeignKey("cases.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "evidence_id",
            sa.BigInteger(),
            sa.ForeignKey("evidence_objects.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        _tenant_col(),
    )

    op.create_table(
        "case_notes",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        _tenant_col(),
        sa.Column(
            "case_id",
            sa.BigInteger(),
            sa.ForeignKey("cases.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "author_user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index("ix_case_notes_case", "case_notes", ["case_id"])

    for table in ("cases", "case_evidence", "case_notes"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(f"CREATE POLICY tenant_isolation ON {table} {_RLS}")


def downgrade() -> None:
    op.drop_table("case_notes")
    op.drop_table("case_evidence")
    op.drop_table("cases")
