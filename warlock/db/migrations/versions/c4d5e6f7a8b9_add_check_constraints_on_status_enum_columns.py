"""Add CHECK constraints on status/enum columns (H-14)

Revision ID: c4d5e6f7a8b9
Revises: b3c4d5e6f7a8
Create Date: 2026-03-23

H-14: Add CHECK constraints to the most critical status/enum columns to prevent
invalid values from being inserted. Covers 8 tables: connector_runs, findings,
control_results (status + severity), issues, poams, compensating_controls,
risk_acceptances, and attestations.
"""

from typing import Sequence, Union

from alembic import op


revision: str = "c4d5e6f7a8b9"
down_revision: Union[str, Sequence[str], None] = "b3c4d5e6f7a8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Map of (table_name, constraint_name, check_expression)
_CONSTRAINTS = [
    (
        "connector_runs",
        "ck_connector_runs_status",
        "status IN ('running','success','partial','error')",
    ),
    (
        "findings",
        "ck_findings_severity",
        "severity IN ('critical','high','medium','low','info')",
    ),
    (
        "control_results",
        "ck_control_results_status",
        "status IN ('compliant','non_compliant','partial','not_assessed',"
        "'not_applicable','risk_accepted','inherited_compliant','inherited_at_risk')",
    ),
    (
        "control_results",
        "ck_control_results_severity",
        "severity IN ('critical','high','medium','low','info')",
    ),
    (
        "issues",
        "ck_issues_status",
        "status IN ('open','assigned','in_progress','remediated','verified','closed','risk_accepted')",
    ),
    (
        "poams",
        "ck_poams_status",
        "status IN ('draft','open','in_progress','completed','verified','closed')",
    ),
    (
        "compensating_controls",
        "ck_compensating_controls_status",
        "status IN ('proposed','approved','active','expired','revoked')",
    ),
    (
        "risk_acceptances",
        "ck_risk_acceptances_status",
        "status IN ('requested','reviewed','approved','active','expired','revoked')",
    ),
    (
        "attestations",
        "ck_attestations_status",
        "status IN ('draft','submitted','reviewed','approved','rejected')",
    ),
]


def upgrade() -> None:
    for table, name, expr in _CONSTRAINTS:
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.create_check_constraint(name, condition=expr)


def downgrade() -> None:
    for table, name, _expr in reversed(_CONSTRAINTS):
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.drop_constraint(name, type_="check")
