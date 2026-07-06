"""event_techniques: add mapping_source + confidence

Revision ID: 0005

Records HOW each technique mapping was derived (vendor / rules / ai) and
a 0-100 confidence, so coverage can be broken down by provenance and the
future AI classifier can be trusted-but-verified against deterministic
rules and vendor ground truth.
"""

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "event_techniques",
        sa.Column("mapping_source", sa.Text(), nullable=False, server_default=sa.text("'vendor'")),
    )
    op.add_column(
        "event_techniques",
        sa.Column("confidence", sa.SmallInteger(), nullable=False, server_default=sa.text("100")),
    )
    op.create_index(
        "ix_event_techniques_tenant_source",
        "event_techniques",
        ["tenant_id", "mapping_source"],
    )


def downgrade() -> None:
    op.drop_index("ix_event_techniques_tenant_source", table_name="event_techniques")
    op.drop_column("event_techniques", "confidence")
    op.drop_column("event_techniques", "mapping_source")
