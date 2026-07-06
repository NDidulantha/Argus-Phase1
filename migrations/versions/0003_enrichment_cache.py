"""enrichment_cache: global threat-intel verdict cache

Revision ID: 0003

Deliberately NO tenant_id and NO RLS: indicator reputation is shared
world knowledge, and a global cache means one provider API call serves
all tenants (quota protection is a first-class design goal here).
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "enrichment_cache",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column("provider", sa.Text(), nullable=False),
        sa.Column("indicator_type", sa.Text(), nullable=False),
        sa.Column("indicator_value", sa.Text(), nullable=False),
        sa.Column("score", sa.SmallInteger(), nullable=True),
        sa.Column("verdict", sa.Text(), nullable=False, server_default=sa.text("'unknown'")),
        sa.Column("raw", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column(
            "fetched_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint(
            "provider", "indicator_type", "indicator_value", name="uq_enrichment_indicator"
        ),
    )


def downgrade() -> None:
    op.drop_table("enrichment_cache")
