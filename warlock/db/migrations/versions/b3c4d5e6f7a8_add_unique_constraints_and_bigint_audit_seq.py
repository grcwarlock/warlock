"""Add unique constraints on ControlResult/PostureSnapshot and fix audit sequence to BigInteger

Revision ID: b3c4d5e6f7a8
Revises: a2b3c4d5e6f7
Create Date: 2026-03-23

H-35: Add UniqueConstraint on ControlResult (finding_id, control_mapping_id, system_profile_id)
      and PostureSnapshot (snapshot_date, framework, control_id, system_profile_id) to prevent
      duplicate results that corrupt posture calculations.
H-36: Alter audit_entries.sequence from Integer to BigInteger. The initial migration (735d585d425d)
      created it as sa.Integer() but the model defines BigInteger. High-volume audit trails
      will overflow a 32-bit integer.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "b3c4d5e6f7a8"
down_revision: Union[str, Sequence[str], None] = "a2b3c4d5e6f7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # H-35: Unique constraint on control_results natural key
    with op.batch_alter_table("control_results", schema=None) as batch_op:
        batch_op.create_unique_constraint(
            "uq_result_finding_mapping_system",
            ["finding_id", "control_mapping_id", "system_profile_id"],
        )

    # H-35: Unique constraint on posture_snapshots natural key
    with op.batch_alter_table("posture_snapshots", schema=None) as batch_op:
        batch_op.create_unique_constraint(
            "uq_posture_date_framework_control_system",
            ["snapshot_date", "framework", "control_id", "system_profile_id"],
        )

    # H-36: Alter audit_entries.sequence from Integer to BigInteger
    with op.batch_alter_table("audit_entries", schema=None) as batch_op:
        batch_op.alter_column(
            "sequence",
            existing_type=sa.Integer(),
            type_=sa.BigInteger(),
            existing_nullable=False,
        )


def downgrade() -> None:
    # H-36: Revert audit_entries.sequence back to Integer
    with op.batch_alter_table("audit_entries", schema=None) as batch_op:
        batch_op.alter_column(
            "sequence",
            existing_type=sa.BigInteger(),
            type_=sa.Integer(),
            existing_nullable=False,
        )

    # H-35: Remove unique constraint on posture_snapshots
    with op.batch_alter_table("posture_snapshots", schema=None) as batch_op:
        batch_op.drop_constraint("uq_posture_date_framework_control_system", type_="unique")

    # H-35: Remove unique constraint on control_results
    with op.batch_alter_table("control_results", schema=None) as batch_op:
        batch_op.drop_constraint("uq_result_finding_mapping_system", type_="unique")
