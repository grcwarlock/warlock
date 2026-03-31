"""JSONB column migration, materialized views, and composite index on control_results

Revision ID: b1c2d3e4f5a6
Revises: a1b2c3d4e5f6
Create Date: 2026-03-19 14:00:00.000000

Applies three P0 performance enhancements:

#9 - JSON -> JSONB: On PostgreSQL, alters high-volume JSON columns to JSONB
     for GIN index support, containment operators (@>), and better compression.
     Columns affected: raw_events.raw_data, findings.detail, control_mappings.crosswalk_path,
     control_results.assertion_findings, control_results.remediation_steps,
     control_results.evidence_ids, posture_snapshots.evidence_sources,
     change_events.detail, audit_evidence_requests.evidence_ids
     SQLite: no-op (JSON and JSONB are equivalent there)

#10 - Materialized views: Creates mv_coverage_summary, mv_latest_posture, and
      mv_framework_rollup on PostgreSQL for fast dashboard/reporting queries.
      SQLite: no-op; API falls back to direct queries.

#11 - Composite index: idx_result_fw_status_assessed on control_results
      (framework, status, assessed_at) — covers the primary dashboard filter
      pattern and eliminates full table scans on posture rollup queries.
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "b1c2d3e4f5a6"
down_revision: Union[str, Sequence[str], None] = "a1b2c3d4e5f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _is_postgresql() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def upgrade() -> None:
    # ------------------------------------------------------------------
    # #11: Composite index on control_results (runs on both SQLite and PG)
    # ------------------------------------------------------------------
    with op.batch_alter_table("control_results", schema=None) as batch_op:
        batch_op.create_index(
            "idx_result_fw_status_assessed",
            ["framework", "status", "assessed_at"],
        )

    # ------------------------------------------------------------------
    # PostgreSQL-only changes below
    # ------------------------------------------------------------------
    if not _is_postgresql():
        return

    # ------------------------------------------------------------------
    # #9: Alter high-volume JSON columns to JSONB on PostgreSQL
    # ------------------------------------------------------------------
    jsonb = sa.dialects.postgresql.JSONB()

    # raw_events.raw_data
    op.alter_column(
        "raw_events",
        "raw_data",
        type_=jsonb,
        existing_nullable=False,
        postgresql_using="raw_data::jsonb",
    )

    # findings.detail
    op.alter_column(
        "findings", "detail", type_=jsonb, existing_nullable=False, postgresql_using="detail::jsonb"
    )

    # control_mappings.crosswalk_path
    op.alter_column(
        "control_mappings",
        "crosswalk_path",
        type_=jsonb,
        existing_nullable=True,
        postgresql_using="crosswalk_path::jsonb",
    )

    # control_results.assertion_findings
    op.alter_column(
        "control_results",
        "assertion_findings",
        type_=jsonb,
        existing_nullable=True,
        postgresql_using="assertion_findings::jsonb",
    )

    # control_results.remediation_steps
    op.alter_column(
        "control_results",
        "remediation_steps",
        type_=jsonb,
        existing_nullable=True,
        postgresql_using="remediation_steps::jsonb",
    )

    # control_results.evidence_ids
    op.alter_column(
        "control_results",
        "evidence_ids",
        type_=jsonb,
        existing_nullable=True,
        postgresql_using="evidence_ids::jsonb",
    )

    # posture_snapshots.evidence_sources
    op.alter_column(
        "posture_snapshots",
        "evidence_sources",
        type_=jsonb,
        existing_nullable=True,
        postgresql_using="evidence_sources::jsonb",
    )

    # change_events.detail
    op.alter_column(
        "change_events",
        "detail",
        type_=jsonb,
        existing_nullable=True,
        postgresql_using="detail::jsonb",
    )

    # audit_evidence_requests.evidence_ids
    op.alter_column(
        "audit_evidence_requests",
        "evidence_ids",
        type_=jsonb,
        existing_nullable=True,
        postgresql_using="evidence_ids::jsonb",
    )

    # ------------------------------------------------------------------
    # #10: Materialized views for coverage, posture, and framework rollups
    # ------------------------------------------------------------------
    conn = op.get_bind()

    conn.execute(
        sa.text("""
        CREATE MATERIALIZED VIEW IF NOT EXISTS mv_coverage_summary AS
        SELECT
            framework,
            status,
            COUNT(*)                    AS result_count,
            COUNT(DISTINCT control_id)  AS control_count
        FROM control_results
        GROUP BY framework, status
    """)
    )
    conn.execute(
        sa.text(
            "CREATE UNIQUE INDEX IF NOT EXISTS "
            "uix_mv_coverage_summary_fw_status "
            "ON mv_coverage_summary (framework, status)"
        )
    )

    conn.execute(
        sa.text("""
        CREATE MATERIALIZED VIEW IF NOT EXISTS mv_latest_posture AS
        SELECT DISTINCT ON (framework, control_id)
            framework,
            control_id,
            status,
            posture_score,
            evidence_sources,
            created_at
        FROM posture_snapshots
        ORDER BY framework, control_id, created_at DESC
    """)
    )
    conn.execute(
        sa.text(
            "CREATE UNIQUE INDEX IF NOT EXISTS "
            "uix_mv_latest_posture_fw_ctrl "
            "ON mv_latest_posture (framework, control_id)"
        )
    )

    conn.execute(
        sa.text("""
        CREATE MATERIALIZED VIEW IF NOT EXISTS mv_framework_rollup AS
        SELECT
            framework,
            COUNT(DISTINCT control_id)                          AS total_controls,
            COUNT(DISTINCT control_id) FILTER (
                WHERE status = 'compliant'
            )                                                   AS compliant_controls,
            COUNT(DISTINCT control_id) FILTER (
                WHERE status = 'non_compliant'
            )                                                   AS non_compliant_controls,
            COUNT(DISTINCT control_id) FILTER (
                WHERE status IN ('partial', 'not_assessed')
            )                                                   AS partial_controls,
            ROUND(
                100.0 * COUNT(DISTINCT control_id) FILTER (WHERE status = 'compliant')
                / NULLIF(COUNT(DISTINCT control_id), 0),
                2
            )                                                   AS compliance_pct
        FROM control_results
        GROUP BY framework
    """)
    )
    conn.execute(
        sa.text(
            "CREATE UNIQUE INDEX IF NOT EXISTS "
            "uix_mv_framework_rollup_fw "
            "ON mv_framework_rollup (framework)"
        )
    )


def downgrade() -> None:
    # ------------------------------------------------------------------
    # #11: Drop composite index (both dialects)
    # ------------------------------------------------------------------
    with op.batch_alter_table("control_results", schema=None) as batch_op:
        batch_op.drop_index("idx_result_fw_status_assessed")

    if not _is_postgresql():
        return

    # ------------------------------------------------------------------
    # #10: Drop materialized views
    # ------------------------------------------------------------------
    conn = op.get_bind()
    conn.execute(sa.text("DROP MATERIALIZED VIEW IF EXISTS mv_framework_rollup"))
    conn.execute(sa.text("DROP MATERIALIZED VIEW IF EXISTS mv_latest_posture"))
    conn.execute(sa.text("DROP MATERIALIZED VIEW IF EXISTS mv_coverage_summary"))

    # ------------------------------------------------------------------
    # #9: Revert JSONB columns back to JSON
    # ------------------------------------------------------------------
    json_type = sa.dialects.postgresql.JSON()

    op.alter_column(
        "audit_evidence_requests",
        "evidence_ids",
        type_=json_type,
        existing_nullable=True,
        postgresql_using="evidence_ids::json",
    )
    op.alter_column(
        "change_events",
        "detail",
        type_=json_type,
        existing_nullable=True,
        postgresql_using="detail::json",
    )
    op.alter_column(
        "posture_snapshots",
        "evidence_sources",
        type_=json_type,
        existing_nullable=True,
        postgresql_using="evidence_sources::json",
    )
    op.alter_column(
        "control_results",
        "evidence_ids",
        type_=json_type,
        existing_nullable=True,
        postgresql_using="evidence_ids::json",
    )
    op.alter_column(
        "control_results",
        "remediation_steps",
        type_=json_type,
        existing_nullable=True,
        postgresql_using="remediation_steps::json",
    )
    op.alter_column(
        "control_results",
        "assertion_findings",
        type_=json_type,
        existing_nullable=True,
        postgresql_using="assertion_findings::json",
    )
    op.alter_column(
        "control_mappings",
        "crosswalk_path",
        type_=json_type,
        existing_nullable=True,
        postgresql_using="crosswalk_path::json",
    )
    op.alter_column(
        "findings",
        "detail",
        type_=json_type,
        existing_nullable=False,
        postgresql_using="detail::json",
    )
    op.alter_column(
        "raw_events",
        "raw_data",
        type_=json_type,
        existing_nullable=False,
        postgresql_using="raw_data::json",
    )
