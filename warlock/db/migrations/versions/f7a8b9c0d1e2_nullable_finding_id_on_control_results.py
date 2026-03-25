"""Make finding_id and control_mapping_id nullable on control_results for OPA results.

OPA compliance evaluation produces control-level results that are not tied to any
individual finding or mapping.  They are framework-wide policy verdicts.

Revision ID: f7a8b9c0d1e2
Revises: e6f7a8b9c0d1
Create Date: 2026-03-25
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "f7a8b9c0d1e2"
down_revision = "e6f7a8b9c0d1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # SQLite doesn't support ALTER COLUMN, so we use batch mode
    with op.batch_alter_table("control_results") as batch_op:
        batch_op.alter_column("finding_id", existing_type=sa.String(36), nullable=True)
        batch_op.alter_column("control_mapping_id", existing_type=sa.String(36), nullable=True)


def downgrade() -> None:
    with op.batch_alter_table("control_results") as batch_op:
        batch_op.alter_column("finding_id", existing_type=sa.String(36), nullable=False)
        batch_op.alter_column("control_mapping_id", existing_type=sa.String(36), nullable=False)
