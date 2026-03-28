"""Add missing model columns to findings, control_results, issues, poams, risk_analyses, users.

Revision ID: e6f7a8b9c0d1
Revises: d5e6f7a8b9c0
Create Date: 2026-03-24
"""

from alembic import op
import sqlalchemy as sa

revision = "e6f7a8b9c0d1"
down_revision = "d5e6f7a8b9c0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("findings") as batch_op:
        batch_op.add_column(sa.Column("classification", sa.String(50), nullable=True))

    with op.batch_alter_table("control_results") as batch_op:
        batch_op.add_column(sa.Column("inherent_risk_ale", sa.Float(), nullable=True))

    with op.batch_alter_table("issues") as batch_op:
        batch_op.add_column(sa.Column("root_cause_id", sa.String(36), nullable=True))

    with op.batch_alter_table("poams") as batch_op:
        batch_op.add_column(sa.Column("cost_estimate", sa.Float(), nullable=True))
        batch_op.add_column(
            sa.Column("escalation_level", sa.Integer(), nullable=True, server_default="0")
        )
        batch_op.add_column(
            sa.Column("escalation_sent_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.add_column(sa.Column("resource_allocation", sa.Text(), nullable=True))

    with op.batch_alter_table("risk_analyses") as batch_op:
        batch_op.add_column(sa.Column("mttr_days", sa.Float(), nullable=True))
        batch_op.add_column(sa.Column("risk_culture_score", sa.Float(), nullable=True))

    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(sa.Column("delegated_by", sa.String(36), nullable=True))
        batch_op.add_column(
            sa.Column("max_concurrent_sessions", sa.Integer(), nullable=True, server_default="5")
        )
        batch_op.add_column(sa.Column("parent_role", sa.String(50), nullable=True))
        batch_op.add_column(
            sa.Column("session_expires_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.add_column(sa.Column("sso_provider", sa.String(50), nullable=True))
        batch_op.add_column(sa.Column("sso_subject_id", sa.String(255), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("sso_subject_id")
        batch_op.drop_column("sso_provider")
        batch_op.drop_column("session_expires_at")
        batch_op.drop_column("parent_role")
        batch_op.drop_column("max_concurrent_sessions")
        batch_op.drop_column("delegated_by")

    with op.batch_alter_table("risk_analyses") as batch_op:
        batch_op.drop_column("risk_culture_score")
        batch_op.drop_column("mttr_days")

    with op.batch_alter_table("poams") as batch_op:
        batch_op.drop_column("resource_allocation")
        batch_op.drop_column("escalation_sent_at")
        batch_op.drop_column("escalation_level")
        batch_op.drop_column("cost_estimate")

    with op.batch_alter_table("issues") as batch_op:
        batch_op.drop_column("root_cause_id")

    with op.batch_alter_table("control_results") as batch_op:
        batch_op.drop_column("inherent_risk_ale")

    with op.batch_alter_table("findings") as batch_op:
        batch_op.drop_column("classification")
