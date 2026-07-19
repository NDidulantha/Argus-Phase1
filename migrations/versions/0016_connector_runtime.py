"""connectors: runtime polling columns (enabled, cursor, last_run bookkeeping)

The connector runtime (services/connector_runtime.py) polls each enabled
connector on a timer, pulling new events since a per-connector resume cursor
and feeding them through the normal ingest path. These columns hold that
state: `enabled` gates whether the runtime touches a connector at all,
`cursor` is the opaque per-vendor resume token (Wazuh: last @timestamp seen),
and last_run_at / last_ingested record the most recent poll for the UI.

Revision ID: 0016
"""

import sqlalchemy as sa
from alembic import op

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "connectors",
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
    )
    op.add_column("connectors", sa.Column("cursor", sa.Text(), nullable=True))
    op.add_column(
        "connectors",
        sa.Column("last_run_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )
    op.add_column(
        "connectors",
        sa.Column("last_ingested", sa.Integer(), nullable=False, server_default=sa.text("0")),
    )


def downgrade() -> None:
    op.drop_column("connectors", "last_ingested")
    op.drop_column("connectors", "last_run_at")
    op.drop_column("connectors", "cursor")
    op.drop_column("connectors", "enabled")
