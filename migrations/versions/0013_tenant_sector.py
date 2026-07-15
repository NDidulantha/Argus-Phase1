"""tenants: sector label for the MSSP control plane

Revision ID: 0013
"""

import sqlalchemy as sa
from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("tenants", sa.Column("sector", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("tenants", "sector")
