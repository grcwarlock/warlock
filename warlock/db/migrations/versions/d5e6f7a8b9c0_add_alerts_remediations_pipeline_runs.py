"""Add alerts, remediations, and pipeline_runs tables (PG-1, PG-7, PG-8)

Revision ID: d5e6f7a8b9c0
Revises: c4d5e6f7a8b9
Create Date: 2026-03-23

PG-1: Alert model for rule-triggered notifications with MITRE ATT&CK support.
PG-7: Remediation model with 5-stage workflow (open->assigned->in_progress->verification->closed).
PG-8: PipelineRun model for pipeline execution history and stats.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "d5e6f7a8b9c0"
down_revision: Union[str, Sequence[str], None] = "c4d5e6f7a8b9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- alerts ---
    op.create_table(
        "alerts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("title", sa.Text, nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("category", sa.String(50), nullable=False),
        sa.Column(
            "finding_id",
            sa.String(36),
            sa.ForeignKey("findings.id", ondelete="SET NULL"),
        ),
        sa.Column(
            "control_result_id",
            sa.String(36),
            sa.ForeignKey("control_results.id", ondelete="SET NULL"),
        ),
        sa.Column("connector_name", sa.String(100)),
        sa.Column("framework", sa.String(50)),
        sa.Column("control_id", sa.String(50)),
        sa.Column("mitre_tactic", sa.String(100)),
        sa.Column("mitre_technique", sa.String(100)),
        sa.Column("status", sa.String(20), nullable=False, server_default="open"),
        sa.Column("acknowledged_by", sa.String(255)),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True)),
        sa.Column("resolved_by", sa.String(255)),
        sa.Column("resolved_at", sa.DateTime(timezone=True)),
        sa.Column("resolution_notes", sa.Text),
        sa.Column("rule_name", sa.String(255)),
        sa.Column("rule_metadata", sa.JSON, server_default="{}"),
        sa.Column("triggered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "status IN ('open','acknowledged','investigating','resolved','dismissed')",
            name="ck_alerts_status",
        ),
        sa.CheckConstraint(
            "severity IN ('critical','high','medium','low','info')",
            name="ck_alerts_severity",
        ),
    )
    op.create_index("idx_alert_status", "alerts", ["status"])
    op.create_index("idx_alert_severity", "alerts", ["severity"])
    op.create_index("idx_alert_category", "alerts", ["category"])
    op.create_index("idx_alert_triggered_at", "alerts", ["triggered_at"])
    op.create_index("idx_alert_finding_id", "alerts", ["finding_id"])
    op.create_index("idx_alert_control_result_id", "alerts", ["control_result_id"])

    # --- remediations ---
    op.create_table(
        "remediations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("title", sa.Text, nullable=False),
        sa.Column("description", sa.Text),
        sa.Column(
            "finding_id",
            sa.String(36),
            sa.ForeignKey("findings.id", ondelete="SET NULL"),
        ),
        sa.Column(
            "control_result_id",
            sa.String(36),
            sa.ForeignKey("control_results.id", ondelete="SET NULL"),
        ),
        sa.Column(
            "alert_id",
            sa.String(36),
            sa.ForeignKey("alerts.id", ondelete="SET NULL"),
        ),
        sa.Column(
            "issue_id",
            sa.String(36),
            sa.ForeignKey("issues.id", ondelete="SET NULL"),
        ),
        sa.Column("framework", sa.String(50)),
        sa.Column("control_id", sa.String(50)),
        sa.Column("status", sa.String(20), nullable=False, server_default="open"),
        sa.Column("assigned_to", sa.String(255)),
        sa.Column("assigned_by", sa.String(255)),
        sa.Column("assigned_at", sa.DateTime(timezone=True)),
        sa.Column("remediation_plan", sa.Text),
        sa.Column("remediation_steps", sa.JSON, server_default="[]"),
        sa.Column("evidence", sa.JSON, server_default="[]"),
        sa.Column("verified_by", sa.String(255)),
        sa.Column("verified_at", sa.DateTime(timezone=True)),
        sa.Column("verification_notes", sa.Text),
        sa.Column("due_date", sa.DateTime(timezone=True)),
        sa.Column("closed_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
        sa.Column("created_by", sa.String(255)),
        sa.CheckConstraint(
            "status IN ('open','assigned','in_progress','verification','closed')",
            name="ck_remediations_status",
        ),
    )
    op.create_index("idx_remediation_status", "remediations", ["status"])
    op.create_index("idx_remediation_finding_id", "remediations", ["finding_id"])
    op.create_index("idx_remediation_control_result_id", "remediations", ["control_result_id"])
    op.create_index("idx_remediation_alert_id", "remediations", ["alert_id"])
    op.create_index("idx_remediation_assigned_to", "remediations", ["assigned_to"])
    op.create_index("idx_remediation_due_date", "remediations", ["due_date"])

    # --- pipeline_runs ---
    op.create_table(
        "pipeline_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="running"),
        sa.Column("connectors_succeeded", sa.Integer, server_default="0"),
        sa.Column("connectors_failed", sa.Integer, server_default="0"),
        sa.Column("raw_events_collected", sa.Integer, server_default="0"),
        sa.Column("findings_normalized", sa.Integer, server_default="0"),
        sa.Column("controls_mapped", sa.Integer, server_default="0"),
        sa.Column("errors", sa.JSON, server_default="[]"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("duration_seconds", sa.Float),
        sa.Column("triggered_by", sa.String(255)),
        sa.Column("source_filter", sa.JSON, server_default="[]"),
        sa.CheckConstraint(
            "status IN ('running','completed','failed')",
            name="ck_pipeline_runs_status",
        ),
    )
    op.create_index("idx_pipeline_run_status", "pipeline_runs", ["status"])
    op.create_index("idx_pipeline_run_started_at", "pipeline_runs", ["started_at"])


def downgrade() -> None:
    op.drop_table("pipeline_runs")
    op.drop_table("remediations")
    op.drop_table("alerts")
