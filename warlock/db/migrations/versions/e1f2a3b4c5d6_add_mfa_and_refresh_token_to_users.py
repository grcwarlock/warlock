"""Add MFA fields and refresh_token_hash to users table

Revision ID: e1f2a3b4c5d6
Revises: d4e5f6a7b8c9
Create Date: 2026-03-19 14:00:00.000000

Adds columns to users that were declared in the model but never migrated:
- mfa_enabled (Boolean, default False)
- mfa_secret (String 64, nullable)
- mfa_backup_codes (JSON, nullable)
- mfa_verified_at (DateTime, nullable)
- refresh_token_hash (String 64, nullable)
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
try:
    from sqlalchemy.dialects import sqlite
    SQLiteJSON = sqlite.JSON
except ImportError:
    SQLiteJSON = sa.JSON

# revision identifiers
revision = "e1f2a3b4c5d6"
down_revision = "d4e5f6a7b8c9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("mfa_enabled", sa.Boolean(), nullable=True, server_default="0")
        )
        batch_op.add_column(
            sa.Column("mfa_secret", sa.String(64), nullable=True)
        )
        batch_op.add_column(
            sa.Column("mfa_backup_codes", sa.JSON(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("mfa_verified_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.add_column(
            sa.Column("refresh_token_hash", sa.String(64), nullable=True)
        )


def downgrade() -> None:
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.drop_column("refresh_token_hash")
        batch_op.drop_column("mfa_verified_at")
        batch_op.drop_column("mfa_backup_codes")
        batch_op.drop_column("mfa_secret")
        batch_op.drop_column("mfa_enabled")
