"""evidence_objects: summary_text + embedding vector for RAG

Revision ID: 0008
"""

import sqlalchemy as sa
from alembic import op
from pgvector.sqlalchemy import Vector

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("evidence_objects", sa.Column("summary_text", sa.Text(), nullable=True))
    op.add_column("evidence_objects", sa.Column("embedding", Vector(384), nullable=True))
    op.add_column(
        "evidence_objects", sa.Column("embedding_provider", sa.Text(), nullable=True)
    )
    # IVFFlat index for cosine similarity search. lists=100 is fine for
    # dev volume; tune with data size in production.
    op.execute(
        "CREATE INDEX ix_evidence_embedding ON evidence_objects "
        "USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_evidence_embedding")
    op.drop_column("evidence_objects", "embedding_provider")
    op.drop_column("evidence_objects", "embedding")
    op.drop_column("evidence_objects", "summary_text")
