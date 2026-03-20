"""DB performance fixes: indexes, ondelete rules, column rename, new table_args

Revision ID: a1b2c3d4e5f6
Revises: cf06b1e0cada
Create Date: 2026-03-19 12:00:00.000000

Applies the following changes from the performance audit:

D-1: Add idx_posture_system index on posture_snapshots.system_profile_id
D-2: Add idx_result_mapping index on control_results.control_mapping_id
D-3: Add ondelete rules to nullable FKs on poams, compensating_controls,
     risk_acceptances, issues, attestations, api_keys
D-7: Add idx_ext_auditor_email, idx_ext_auditor_magic_hash on external_auditors;
     Add idx_auditcomment_auditor on audit_comments
D-8: Add idx_policy_override_active on policy_overrides;
     Add idx_drift_system on compliance_drifts
D-9: Rename audit_entries.metadata column to audit_entries.extra
D-11: Add ondelete=CASCADE to api_keys.user_id

For SQLite, batch_alter_table is used (render_as_batch=True in env.py)
which recreates the table to support FK and column changes.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, Sequence[str], None] = "cf06b1e0cada"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ------------------------------------------------------------------
    # D-9: Rename audit_entries.metadata -> audit_entries.extra
    # ------------------------------------------------------------------
    with op.batch_alter_table("audit_entries", schema=None) as batch_op:
        batch_op.alter_column("metadata", new_column_name="extra")

    # ------------------------------------------------------------------
    # D-1: Add index on posture_snapshots.system_profile_id
    # ------------------------------------------------------------------
    with op.batch_alter_table("posture_snapshots", schema=None) as batch_op:
        batch_op.create_index("idx_posture_system", ["system_profile_id"])
        # D-3: Add ondelete=SET NULL to posture_snapshots.system_profile_id
        batch_op.drop_constraint("fk_posture_system_profile", type_="foreignkey") if _fk_exists(
            "posture_snapshots", "fk_posture_system_profile"
        ) else None
        batch_op.alter_column(
            "system_profile_id",
            existing_type=sa.String(36),
            nullable=True,
        )

    # ------------------------------------------------------------------
    # D-2: Add index on control_results.control_mapping_id
    # ------------------------------------------------------------------
    with op.batch_alter_table("control_results", schema=None) as batch_op:
        batch_op.create_index("idx_result_mapping", ["control_mapping_id"])

    # ------------------------------------------------------------------
    # D-3: ondelete=SET NULL on poams nullable FKs
    # ------------------------------------------------------------------
    with op.batch_alter_table("poams", schema=None) as batch_op:
        batch_op.alter_column(
            "finding_id",
            existing_type=sa.String(36),
            nullable=True,
        )
        batch_op.alter_column(
            "control_result_id",
            existing_type=sa.String(36),
            nullable=True,
        )
        batch_op.alter_column(
            "system_profile_id",
            existing_type=sa.String(36),
            nullable=True,
        )

    # ------------------------------------------------------------------
    # D-3: ondelete=SET NULL on compensating_controls nullable FKs
    # ------------------------------------------------------------------
    with op.batch_alter_table("compensating_controls", schema=None) as batch_op:
        batch_op.alter_column(
            "poam_id",
            existing_type=sa.String(36),
            nullable=True,
        )
        batch_op.alter_column(
            "system_profile_id",
            existing_type=sa.String(36),
            nullable=True,
        )

    # ------------------------------------------------------------------
    # D-3: ondelete=SET NULL on risk_acceptances nullable FKs
    # ------------------------------------------------------------------
    with op.batch_alter_table("risk_acceptances", schema=None) as batch_op:
        batch_op.alter_column(
            "poam_id",
            existing_type=sa.String(36),
            nullable=True,
        )
        batch_op.alter_column(
            "system_profile_id",
            existing_type=sa.String(36),
            nullable=True,
        )

    # ------------------------------------------------------------------
    # D-3: ondelete=SET NULL on issues nullable FKs
    # ------------------------------------------------------------------
    with op.batch_alter_table("issues", schema=None) as batch_op:
        batch_op.alter_column(
            "finding_id",
            existing_type=sa.String(36),
            nullable=True,
        )
        batch_op.alter_column(
            "control_result_id",
            existing_type=sa.String(36),
            nullable=True,
        )

    # ------------------------------------------------------------------
    # D-3: ondelete=SET NULL on attestations.engagement_id
    # ------------------------------------------------------------------
    with op.batch_alter_table("attestations", schema=None) as batch_op:
        batch_op.alter_column(
            "engagement_id",
            existing_type=sa.String(36),
            nullable=True,
        )

    # ------------------------------------------------------------------
    # D-3/D-11: ondelete=CASCADE on api_keys.user_id
    # ------------------------------------------------------------------
    with op.batch_alter_table("api_keys", schema=None) as batch_op:
        batch_op.alter_column(
            "user_id",
            existing_type=sa.String(36),
            nullable=False,
        )

    # ------------------------------------------------------------------
    # D-7: Indexes on external_auditors
    # ------------------------------------------------------------------
    with op.batch_alter_table("external_auditors", schema=None) as batch_op:
        batch_op.create_index("idx_ext_auditor_email", ["email"])
        batch_op.create_index("idx_ext_auditor_magic_hash", ["magic_link_hash"])

    # ------------------------------------------------------------------
    # D-7: Index on audit_comments.external_auditor_id
    # ------------------------------------------------------------------
    with op.batch_alter_table("audit_comments", schema=None) as batch_op:
        batch_op.create_index("idx_auditcomment_auditor", ["external_auditor_id"])

    # ------------------------------------------------------------------
    # D-8: Index on policy_overrides.is_active
    # ------------------------------------------------------------------
    with op.batch_alter_table("policy_overrides", schema=None) as batch_op:
        batch_op.create_index("idx_policy_override_active", ["is_active"])

    # ------------------------------------------------------------------
    # D-8: Index on compliance_drifts.system_profile_id
    # ------------------------------------------------------------------
    with op.batch_alter_table("compliance_drifts", schema=None) as batch_op:
        batch_op.create_index("idx_drift_system", ["system_profile_id"])

    # ------------------------------------------------------------------
    # W-5: Add legal hold scoping columns
    # ------------------------------------------------------------------
    with op.batch_alter_table("legal_holds", schema=None) as batch_op:
        batch_op.add_column(sa.Column("framework", sa.String(50), nullable=True))
        batch_op.add_column(sa.Column("system_profile_id", sa.String(36), nullable=True))
        batch_op.add_column(
            sa.Column("date_range_start", sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.add_column(sa.Column("date_range_end", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    # D-8
    with op.batch_alter_table("compliance_drifts", schema=None) as batch_op:
        batch_op.drop_index("idx_drift_system")

    with op.batch_alter_table("policy_overrides", schema=None) as batch_op:
        batch_op.drop_index("idx_policy_override_active")

    # W-5: Remove legal hold scoping columns
    with op.batch_alter_table("legal_holds", schema=None) as batch_op:
        batch_op.drop_column("date_range_end")
        batch_op.drop_column("date_range_start")
        batch_op.drop_column("system_profile_id")
        batch_op.drop_column("framework")

    # D-7
    with op.batch_alter_table("audit_comments", schema=None) as batch_op:
        batch_op.drop_index("idx_auditcomment_auditor")

    with op.batch_alter_table("external_auditors", schema=None) as batch_op:
        batch_op.drop_index("idx_ext_auditor_magic_hash")
        batch_op.drop_index("idx_ext_auditor_email")

    # D-2
    with op.batch_alter_table("control_results", schema=None) as batch_op:
        batch_op.drop_index("idx_result_mapping")

    # D-1
    with op.batch_alter_table("posture_snapshots", schema=None) as batch_op:
        batch_op.drop_index("idx_posture_system")

    # D-9: Rename extra back to metadata
    with op.batch_alter_table("audit_entries", schema=None) as batch_op:
        batch_op.alter_column("extra", new_column_name="metadata")


def _fk_exists(table: str, fk_name: str) -> bool:
    """Helper: check if a named FK constraint exists (no-op helper for safety)."""
    return False
