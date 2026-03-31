"""Add pii_detected column to findings table.

Revision ID: a2b3c4d5e6f7
Revises: f2a3b4c5d6e7
Create Date: 2026-03-22
"""

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "a2b3c4d5e6f7"
down_revision = "f2a3b4c5d6e7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("pii_detected", sa.Boolean(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("findings", "pii_detected")
