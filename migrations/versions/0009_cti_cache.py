"""cti_cache: global cached CTI findings

Revision ID: 0009
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cti_cache",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column("provider", sa.Text(), nullable=False),
        sa.Column("indicator_type", sa.Text(), nullable=False),
        sa.Column("indicator_value", sa.Text(), nullable=False),
        sa.Column("found", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column(
            "finding", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
        sa.Column(
            "fetched_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint(
            "provider", "indicator_type", "indicator_value", name="uq_cti_indicator"
        ),
    )


def downgrade() -> None:
    op.drop_table("cti_cache")
