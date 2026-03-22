"""Add missing FK indexes on issues, compensating_controls, risk_acceptances, evidence_requests.

Revision ID: f2a3b4c5d6e7
Revises: e1f2a3b4c5d6
Create Date: 2026-03-21
"""

from alembic import op

# revision identifiers, used by Alembic.
revision = "f2a3b4c5d6e7"
down_revision = "e1f2a3b4c5d6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Issues table — 3 FK indexes
    op.create_index("idx_issue_finding_id", "issues", ["finding_id"])
    op.create_index("idx_issue_control_result_id", "issues", ["control_result_id"])
    op.create_index("idx_issue_poam_id", "issues", ["poam_id"])

    # Compensating controls — 2 FK indexes
    op.create_index("idx_cc_poam_id", "compensating_controls", ["poam_id"])
    op.create_index("idx_cc_system_profile_id", "compensating_controls", ["system_profile_id"])

    # Risk acceptances — 2 FK indexes
    op.create_index("idx_ra_poam_id", "risk_acceptances", ["poam_id"])
    op.create_index("idx_ra_system_profile_id", "risk_acceptances", ["system_profile_id"])

    # Evidence requests — 2 FK indexes
    op.create_index("idx_evidence_req_engagement_id", "evidence_requests", ["engagement_id"])
    op.create_index("idx_evidence_req_auditor_id", "evidence_requests", ["auditor_id"])


def downgrade() -> None:
    op.drop_index("idx_evidence_req_auditor_id", "evidence_requests")
    op.drop_index("idx_evidence_req_engagement_id", "evidence_requests")
    op.drop_index("idx_ra_system_profile_id", "risk_acceptances")
    op.drop_index("idx_ra_poam_id", "risk_acceptances")
    op.drop_index("idx_cc_system_profile_id", "compensating_controls")
    op.drop_index("idx_cc_poam_id", "compensating_controls")
    op.drop_index("idx_issue_poam_id", "issues")
    op.drop_index("idx_issue_control_result_id", "issues")
    op.drop_index("idx_issue_finding_id", "issues")
