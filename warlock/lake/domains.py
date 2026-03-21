"""Curated zone domain writers for all 10 fact domains.

Each domain has one or more fact/dimension tables.  Writers accept
lists of dicts and write Parquet files to the curated zone with
appropriate partitioning.

Domains:
 1. Compliance Facts (control_results, control_mappings — already in zones.py)
 2. Temporal Facts (posture_snapshots, compliance_drift, regulatory_deadlines)
 3. Risk Facts (risk_simulations, vulnerability_lifecycle, control_effectiveness)
 4. Entity Facts (resources, systems, personnel, vendors, data_silos, software_components)
 5. Governance Facts (poams, issues, attestations, audit_entries, policy_documents, exceptions, legal_holds)
 6. Evidence Facts (evidence_artifacts, evidence_control_bindings, evidence_freshness, evidence_quality)
 7. Privacy Facts (processing_activities, dsars, consent, cross_border_transfers, dpias, breach_register)
 8. Incident Facts (security_events, incidents, notifications, tabletop_exercises)
 9. Pipeline Health Facts (pipeline_runs, connector_runs — partial in zones.py, data_freshness, coverage_metrics)
10. Supply Chain Facts (sbom_components, supplier_assessments, concentration_risk, provenance_attestations)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _today_partition() -> str:
    """Return today's date as YYYY-MM-DD for partitioning."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _write_table(lake_path: str, table_name: str, run_id: str, rows: list[dict]) -> int:
    """Generic writer: dicts -> Parquet in curated/{table_name}/{date}/{run_id}.parquet.

    All dict values are coerced to strings so DuckDB can handle type
    coercion at query time.  Returns row count written.
    """
    import pyarrow as pa
    import pyarrow.parquet as pq

    if not rows:
        return 0

    # Build columnar dict from list-of-dicts, coercing everything to str.
    columns: dict[str, list[str]] = {}
    for key in rows[0]:
        columns[key] = [str(r.get(key, "")) for r in rows]

    table = pa.table(columns)
    date_part = _today_partition()
    out_dir = Path(lake_path) / "curated" / table_name / date_part
    _ensure_dir(out_dir)
    out_file = out_dir / f"{run_id}.parquet"
    pq.write_table(table, str(out_file))
    log.info("Wrote %d rows to %s", len(rows), out_file)
    return len(rows)


def _write_partitioned_by_framework(
    lake_path: str, table_name: str, run_id: str, rows: list[dict]
) -> int:
    """Write rows partitioned by framework/date (like control_results)."""
    import pyarrow as pa
    import pyarrow.parquet as pq

    if not rows:
        return 0

    by_fw: dict[str, list[dict]] = {}
    for r in rows:
        fw = str(r.get("framework", "unknown"))
        by_fw.setdefault(fw, []).append(r)

    total = 0
    date_part = _today_partition()
    for fw, items in by_fw.items():
        columns: dict[str, list[str]] = {}
        for key in items[0]:
            columns[key] = [str(i.get(key, "")) for i in items]

        table = pa.table(columns)
        out_dir = Path(lake_path) / "curated" / table_name / fw / date_part
        _ensure_dir(out_dir)
        out_file = out_dir / f"{run_id}.parquet"
        pq.write_table(table, str(out_file))
        total += len(items)
        log.info("Wrote %d %s rows (%s) to %s", len(items), table_name, fw, out_file)

    return total


# ---------------------------------------------------------------------------
# Domain 2 — Temporal Facts
# ---------------------------------------------------------------------------

def write_temporal_facts(
    lake_path: str,
    run_id: str,
    posture_snapshots: list[dict] | None = None,
    compliance_drifts: list[dict] | None = None,
    regulatory_deadlines: list[dict] | None = None,
) -> int:
    """Write temporal domain tables to curated zone."""
    total = 0
    total += _write_partitioned_by_framework(
        lake_path, "posture_snapshots", run_id, posture_snapshots or []
    )
    total += _write_partitioned_by_framework(
        lake_path, "compliance_drift", run_id, compliance_drifts or []
    )
    total += _write_table(lake_path, "regulatory_deadlines", run_id, regulatory_deadlines or [])
    return total


# ---------------------------------------------------------------------------
# Domain 3 — Risk Facts
# ---------------------------------------------------------------------------

def write_risk_facts(
    lake_path: str,
    run_id: str,
    risk_simulations: list[dict] | None = None,
    vulnerability_lifecycle: list[dict] | None = None,
    control_effectiveness: list[dict] | None = None,
) -> int:
    """Write risk domain tables to curated zone."""
    total = 0
    total += _write_partitioned_by_framework(
        lake_path, "risk_simulations", run_id, risk_simulations or []
    )
    total += _write_table(lake_path, "vulnerability_lifecycle", run_id, vulnerability_lifecycle or [])
    total += _write_partitioned_by_framework(
        lake_path, "control_effectiveness", run_id, control_effectiveness or []
    )
    return total


# ---------------------------------------------------------------------------
# Domain 4 — Entity Facts (SCD Type 2 dimension tables)
# ---------------------------------------------------------------------------

def write_entity_facts(
    lake_path: str,
    run_id: str,
    resources: list[dict] | None = None,
    systems: list[dict] | None = None,
    personnel: list[dict] | None = None,
    vendors: list[dict] | None = None,
    data_silos: list[dict] | None = None,
    software_components: list[dict] | None = None,
) -> int:
    """Write entity dimension tables to curated zone."""
    total = 0
    total += _write_table(lake_path, "resources", run_id, resources or [])
    total += _write_table(lake_path, "systems", run_id, systems or [])
    total += _write_table(lake_path, "personnel", run_id, personnel or [])
    total += _write_table(lake_path, "vendors", run_id, vendors or [])
    total += _write_table(lake_path, "data_silos", run_id, data_silos or [])
    total += _write_table(lake_path, "software_components", run_id, software_components or [])
    return total


# ---------------------------------------------------------------------------
# Domain 5 — Governance Facts
# ---------------------------------------------------------------------------

def write_governance_facts(
    lake_path: str,
    run_id: str,
    poams: list[dict] | None = None,
    issues: list[dict] | None = None,
    attestations: list[dict] | None = None,
    audit_entries: list[dict] | None = None,
    policy_documents: list[dict] | None = None,
    exceptions: list[dict] | None = None,
    legal_holds: list[dict] | None = None,
) -> int:
    """Write governance domain tables to curated zone."""
    total = 0
    total += _write_partitioned_by_framework(
        lake_path, "poams", run_id, poams or []
    )
    total += _write_partitioned_by_framework(
        lake_path, "issues", run_id, issues or []
    )
    total += _write_partitioned_by_framework(
        lake_path, "attestations", run_id, attestations or []
    )
    total += _write_table(lake_path, "audit_entries", run_id, audit_entries or [])
    total += _write_table(lake_path, "policy_documents", run_id, policy_documents or [])
    total += _write_table(lake_path, "exceptions", run_id, exceptions or [])
    total += _write_table(lake_path, "legal_holds", run_id, legal_holds or [])
    return total


# ---------------------------------------------------------------------------
# Domain 6 — Evidence Facts
# ---------------------------------------------------------------------------

def write_evidence_facts(
    lake_path: str,
    run_id: str,
    evidence_artifacts: list[dict] | None = None,
    evidence_control_bindings: list[dict] | None = None,
    evidence_freshness: list[dict] | None = None,
    evidence_quality: list[dict] | None = None,
) -> int:
    """Write evidence domain tables to curated zone."""
    total = 0
    total += _write_table(lake_path, "evidence_artifacts", run_id, evidence_artifacts or [])
    total += _write_table(
        lake_path, "evidence_control_bindings", run_id, evidence_control_bindings or []
    )
    total += _write_table(lake_path, "evidence_freshness", run_id, evidence_freshness or [])
    total += _write_table(lake_path, "evidence_quality", run_id, evidence_quality or [])
    return total


# ---------------------------------------------------------------------------
# Domain 7 — Privacy Facts
# ---------------------------------------------------------------------------

def write_privacy_facts(
    lake_path: str,
    run_id: str,
    processing_activities: list[dict] | None = None,
    dsars: list[dict] | None = None,
    consent: list[dict] | None = None,
    cross_border_transfers: list[dict] | None = None,
    dpias: list[dict] | None = None,
    breach_register: list[dict] | None = None,
) -> int:
    """Write privacy domain tables to curated zone."""
    total = 0
    total += _write_table(
        lake_path, "processing_activities", run_id, processing_activities or []
    )
    total += _write_table(lake_path, "dsars", run_id, dsars or [])
    total += _write_table(lake_path, "consent", run_id, consent or [])
    total += _write_table(
        lake_path, "cross_border_transfers", run_id, cross_border_transfers or []
    )
    total += _write_table(lake_path, "dpias", run_id, dpias or [])
    total += _write_table(lake_path, "breach_register", run_id, breach_register or [])
    return total


# ---------------------------------------------------------------------------
# Domain 8 — Incident Facts
# ---------------------------------------------------------------------------

def write_incident_facts(
    lake_path: str,
    run_id: str,
    security_events: list[dict] | None = None,
    incidents: list[dict] | None = None,
    notifications: list[dict] | None = None,
    tabletop_exercises: list[dict] | None = None,
) -> int:
    """Write incident domain tables to curated zone."""
    total = 0
    total += _write_table(lake_path, "security_events", run_id, security_events or [])
    total += _write_table(lake_path, "incidents", run_id, incidents or [])
    total += _write_table(lake_path, "notifications", run_id, notifications or [])
    total += _write_table(lake_path, "tabletop_exercises", run_id, tabletop_exercises or [])
    return total


# ---------------------------------------------------------------------------
# Domain 9 — Pipeline Health Facts
# ---------------------------------------------------------------------------

def write_pipeline_health_facts(
    lake_path: str,
    run_id: str,
    pipeline_runs: list[dict] | None = None,
    data_freshness: list[dict] | None = None,
    coverage_metrics: list[dict] | None = None,
) -> int:
    """Write pipeline health domain tables to curated zone."""
    total = 0
    total += _write_table(lake_path, "pipeline_runs", run_id, pipeline_runs or [])
    total += _write_table(lake_path, "data_freshness", run_id, data_freshness or [])
    total += _write_table(lake_path, "coverage_metrics", run_id, coverage_metrics or [])
    return total


# ---------------------------------------------------------------------------
# Domain 10 — Supply Chain Facts
# ---------------------------------------------------------------------------

def write_supply_chain_facts(
    lake_path: str,
    run_id: str,
    sbom_components: list[dict] | None = None,
    supplier_assessments: list[dict] | None = None,
    concentration_risk: list[dict] | None = None,
    provenance_attestations: list[dict] | None = None,
) -> int:
    """Write supply chain domain tables to curated zone."""
    total = 0
    total += _write_table(lake_path, "sbom_components", run_id, sbom_components or [])
    total += _write_table(lake_path, "supplier_assessments", run_id, supplier_assessments or [])
    total += _write_table(lake_path, "concentration_risk", run_id, concentration_risk or [])
    total += _write_table(
        lake_path, "provenance_attestations", run_id, provenance_attestations or []
    )
    return total
