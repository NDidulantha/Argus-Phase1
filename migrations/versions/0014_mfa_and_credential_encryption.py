"""users: TOTP MFA columns; connectors: seal plaintext credentials at rest

Revision ID: 0014
"""

import json

import sqlalchemy as sa
from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("mfa_secret", sa.Text(), nullable=True))
    op.add_column(
        "users",
        sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )

    # Seal any plaintext connector credentials with the configured Fernet
    # key. Imported here (not top-level) so alembic can load the file even
    # outside the app venv.
    from argus.core.crypto import encrypt_credentials, is_encrypted

    conn = op.get_bind()
    rows = conn.execute(sa.text("SELECT id, credentials FROM connectors")).all()
    for row_id, credentials in rows:
        stored = credentials if isinstance(credentials, dict) else json.loads(credentials)
        if is_encrypted(stored):
            continue
        conn.execute(
            sa.text("UPDATE connectors SET credentials = :sealed WHERE id = :id"),
            {"sealed": json.dumps(encrypt_credentials(stored)), "id": row_id},
        )


def downgrade() -> None:
    # Credentials stay sealed on downgrade: reads fall back gracefully and
    # decrypting here would write secrets back in plaintext.
    op.drop_column("users", "mfa_enabled")
    op.drop_column("users", "mfa_secret")
