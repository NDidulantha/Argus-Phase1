"""evidence graph: entities + entity_edges (tenant, RLS)

Revision ID: 0006
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None

_RLS = (
    "USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid) "
    "WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)"
)


def upgrade() -> None:
    op.create_table(
        "entities",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("entity_type", sa.Text(), nullable=False),
        sa.Column("entity_key", sa.Text(), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=True),
        sa.Column(
            "attributes", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
        sa.Column("first_seen", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("last_seen", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "entity_type", "entity_key", name="uq_entity_identity"),
    )
    op.create_index("ix_entities_tenant_type", "entities", ["tenant_id", "entity_type"])

    op.create_table(
        "entity_edges",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "src_entity_id",
            sa.BigInteger(),
            sa.ForeignKey("entities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "dst_entity_id",
            sa.BigInteger(),
            sa.ForeignKey("entities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("relation", sa.Text(), nullable=False),
        sa.Column(
            "observation_count", sa.BigInteger(), nullable=False, server_default=sa.text("1")
        ),
        sa.Column("first_seen", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("last_seen", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "tenant_id", "src_entity_id", "dst_entity_id", "relation", name="uq_edge_identity"
        ),
    )
    op.create_index("ix_edges_tenant_src", "entity_edges", ["tenant_id", "src_entity_id"])
    op.create_index("ix_edges_tenant_dst", "entity_edges", ["tenant_id", "dst_entity_id"])

    for tbl in ("entities", "entity_edges"):
        op.execute(f"ALTER TABLE {tbl} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {tbl} FORCE ROW LEVEL SECURITY")
        op.execute(f"CREATE POLICY tenant_isolation ON {tbl} {_RLS}")


def downgrade() -> None:
    op.drop_table("entity_edges")
    op.drop_table("entities")
