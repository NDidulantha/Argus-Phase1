"""hunt_findings: persisted output of the autonomous CTI hunter (tenant, RLS)

The autonomous hunter (services/auto_hunt.py) sweeps every tenant's own
indicators through threat intel on a timer and records the flagged ones
here. It lives in its own table — NOT evidence_objects — because
correlate_tenant() deletes-and-rebuilds open evidence on every pass and
would otherwise wipe these findings. Upsert-keyed on
(tenant_id, indicator_type, value, provider): a re-flagged indicator bumps
last_seen / confidence instead of duplicating.

Revision ID: 0015
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None

_RLS = (
    "USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid) "
    "WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)"
)


def upgrade() -> None:
    op.create_table(
        "hunt_findings",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("indicator_type", sa.Text(), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("provider", sa.Text(), nullable=False),
        sa.Column("confidence", sa.SmallInteger(), nullable=False, server_default=sa.text("0")),
        sa.Column("local_events", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
        sa.Column(
            "finding", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
        sa.Column("status", sa.Text(), nullable=False, server_default=sa.text("'open'")),
        sa.Column(
            "first_seen",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "last_seen",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "indicator_type",
            "value",
            "provider",
            name="uq_hunt_finding",
        ),
    )
    op.create_index(
        "ix_hunt_findings_tenant_conf", "hunt_findings", ["tenant_id", "confidence"]
    )
    op.execute("ALTER TABLE hunt_findings ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE hunt_findings FORCE ROW LEVEL SECURITY")
    op.execute(f"CREATE POLICY tenant_isolation ON hunt_findings {_RLS}")


def downgrade() -> None:
    op.drop_table("hunt_findings")
