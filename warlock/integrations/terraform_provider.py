"""Terraform provider stub for exporting compliance state and validating plans.

Provides a ``TerraformProvider`` that generates Terraform-readable JSON for
compliance state (resource definitions and data sources) and validates
Terraform plans against Warlock compliance policies.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from warlock.config import get_settings

log = logging.getLogger(__name__)


class TerraformProviderError(Exception):
    """Raised when a Terraform provider operation fails."""


class TerraformProvider:
    """Terraform provider stub for Warlock GRC compliance data.

    Exports compliance state as Terraform-readable JSON and validates
    Terraform plans against compliance policies.

    Args:
        session: SQLAlchemy session for querying compliance data.
            If None, methods that need DB access will raise an error.
    """

    def __init__(self, session: Any = None) -> None:
        self._session = session
        self._settings = get_settings()

    # ------------------------------------------------------------------
    # Resource definitions
    # ------------------------------------------------------------------

    def generate_resource_definitions(self, session: Any | None = None) -> dict[str, Any]:
        """Export compliance state as Terraform resource definitions.

        Queries control results, findings, and frameworks from the database
        and formats them as Terraform-compatible JSON that can be consumed
        by ``terraform import`` or a custom Terraform provider.

        Args:
            session: SQLAlchemy session.  Falls back to the instance session.

        Returns:
            Terraform-style JSON with ``resource`` blocks for compliance
            state, findings, and frameworks.
        """
        db = session or self._session
        if db is None:
            raise TerraformProviderError(
                "A database session is required for generate_resource_definitions"
            )

        now = datetime.now(timezone.utc).isoformat()

        # Query frameworks
        frameworks = self._query_frameworks(db)

        # Query summary control result counts per framework
        framework_results = self._query_framework_results(db)

        # Query open findings summary
        findings_summary = self._query_findings_summary(db)

        resources: dict[str, Any] = {
            "terraform": {
                "required_providers": {
                    "warlock": {
                        "source": "warlock-grc/warlock",
                        "version": ">= 0.1.0",
                    }
                }
            },
            "resource": {
                "warlock_compliance_state": {
                    "current": {
                        "generated_at": now,
                        "frameworks": frameworks,
                        "framework_results": framework_results,
                        "findings_summary": findings_summary,
                    }
                }
            },
        }

        log.info(
            "Generated Terraform resource definitions: %d frameworks, %d result sets",
            len(frameworks),
            len(framework_results),
        )
        return resources

    # ------------------------------------------------------------------
    # Data sources
    # ------------------------------------------------------------------

    def generate_data_sources(
        self,
        session: Any | None = None,
        framework: str | None = None,
    ) -> dict[str, Any]:
        """Export control results as a Terraform data source.

        Args:
            session: SQLAlchemy session.
            framework: Optional framework name to filter results.
                If None, returns results across all frameworks.

        Returns:
            Terraform ``data`` block with control result details.
        """
        db = session or self._session
        if db is None:
            raise TerraformProviderError("A database session is required for generate_data_sources")

        now = datetime.now(timezone.utc).isoformat()

        control_results = self._query_control_results(db, framework=framework)

        data_source: dict[str, Any] = {
            "data": {
                "warlock_control_results": {
                    "current": {
                        "generated_at": now,
                        "framework_filter": framework or "all",
                        "total_controls": len(control_results),
                        "controls": control_results,
                    }
                }
            }
        }

        log.info(
            "Generated Terraform data source: %d controls (framework=%s)",
            len(control_results),
            framework or "all",
        )
        return data_source

    # ------------------------------------------------------------------
    # Plan validation
    # ------------------------------------------------------------------

    def validate_plan(self, plan_json: dict[str, Any] | str) -> dict[str, Any]:
        """Validate a Terraform plan against Warlock compliance policies.

        Checks the plan for:
        - Resources being destroyed that have active compliance controls
        - Security group rules that violate compliance baselines
        - Encryption settings that fall below requirements
        - Tagging requirements for compliance tracking

        Args:
            plan_json: Terraform plan output as a dict or JSON string
                (from ``terraform show -json plan.tfplan``).

        Returns:
            Validation result with ``valid`` (bool), ``violations`` (list),
            and ``warnings`` (list).
        """
        if isinstance(plan_json, str):
            try:
                plan_json = json.loads(plan_json)
            except json.JSONDecodeError as exc:
                raise TerraformProviderError(f"Invalid JSON in Terraform plan: {exc}") from exc

        violations: list[dict[str, Any]] = []
        warnings: list[dict[str, Any]] = []

        resource_changes = plan_json.get("resource_changes", [])

        for change in resource_changes:
            resource_type = change.get("type", "")
            resource_name = change.get("name", "")
            address = change.get("address", f"{resource_type}.{resource_name}")
            actions = change.get("change", {}).get("actions", [])
            after = change.get("change", {}).get("after", {}) or {}

            # Check for destruction of compliance-tagged resources
            if "delete" in actions:
                before = change.get("change", {}).get("before", {}) or {}
                tags = before.get("tags", {}) or {}
                if tags.get("compliance") or tags.get("warlock"):
                    violations.append(
                        {
                            "resource": address,
                            "rule": "no_destroy_compliance_resources",
                            "severity": "high",
                            "message": (
                                f"Resource {address} is tagged for compliance "
                                f"tracking and cannot be destroyed without "
                                f"explicit approval."
                            ),
                        }
                    )

            # Check encryption requirements
            if "create" in actions or "update" in actions:
                self._check_encryption(resource_type, address, after, violations, warnings)
                self._check_security_groups(resource_type, address, after, violations, warnings)
                self._check_tagging(resource_type, address, after, warnings)

        valid = len(violations) == 0

        result = {
            "valid": valid,
            "violations": violations,
            "warnings": warnings,
            "summary": {
                "total_resources": len(resource_changes),
                "violation_count": len(violations),
                "warning_count": len(warnings),
            },
        }

        log.info(
            "Terraform plan validation: valid=%s, %d violation(s), %d warning(s)",
            valid,
            len(violations),
            len(warnings),
        )
        return result

    # ------------------------------------------------------------------
    # Compliance policy checks
    # ------------------------------------------------------------------

    @staticmethod
    def _check_encryption(
        resource_type: str,
        address: str,
        after: dict[str, Any],
        violations: list[dict[str, Any]],
        warnings: list[dict[str, Any]],
    ) -> None:
        """Check encryption settings for storage and database resources."""
        encryption_required_types = {
            "aws_s3_bucket",
            "aws_ebs_volume",
            "aws_rds_instance",
            "aws_rds_cluster",
            "aws_db_instance",
            "azurerm_storage_account",
            "azurerm_managed_disk",
            "google_compute_disk",
            "google_sql_database_instance",
        }

        if resource_type not in encryption_required_types:
            return

        # Check various encryption fields
        encrypted = (
            after.get("encrypted")
            or after.get("storage_encrypted")
            or after.get("encryption_at_rest_enabled")
        )

        # Azure storage account
        if resource_type == "azurerm_storage_account":
            encrypted = after.get("enable_https_traffic_only", True)

        if encrypted is False:
            violations.append(
                {
                    "resource": address,
                    "rule": "encryption_required",
                    "severity": "critical",
                    "message": (
                        f"Resource {address} ({resource_type}) must have "
                        f"encryption enabled for compliance."
                    ),
                }
            )

    @staticmethod
    def _check_security_groups(
        resource_type: str,
        address: str,
        after: dict[str, Any],
        violations: list[dict[str, Any]],
        warnings: list[dict[str, Any]],
    ) -> None:
        """Check security group rules for overly permissive access."""
        sg_types = {
            "aws_security_group",
            "aws_security_group_rule",
            "azurerm_network_security_rule",
            "google_compute_firewall",
        }

        if resource_type not in sg_types:
            return

        # Check for 0.0.0.0/0 ingress
        ingress_rules = after.get("ingress", [])
        if isinstance(ingress_rules, list):
            for rule in ingress_rules:
                cidr_blocks = rule.get("cidr_blocks", [])
                if "0.0.0.0/0" in cidr_blocks:
                    from_port = rule.get("from_port", 0)
                    to_port = rule.get("to_port", 65535)
                    # Wide-open port range is a violation
                    if to_port - from_port > 100 or from_port == 0:
                        violations.append(
                            {
                                "resource": address,
                                "rule": "no_wide_open_ingress",
                                "severity": "critical",
                                "message": (
                                    f"Resource {address} allows ingress from "
                                    f"0.0.0.0/0 on ports {from_port}-{to_port}. "
                                    f"This violates network segmentation requirements."
                                ),
                            }
                        )
                    else:
                        warnings.append(
                            {
                                "resource": address,
                                "rule": "public_ingress",
                                "severity": "medium",
                                "message": (
                                    f"Resource {address} allows public ingress "
                                    f"on ports {from_port}-{to_port}. Verify "
                                    f"this is intentional."
                                ),
                            }
                        )

    @staticmethod
    def _check_tagging(
        resource_type: str,
        address: str,
        after: dict[str, Any],
        warnings: list[dict[str, Any]],
    ) -> None:
        """Check that taggable resources have required compliance tags."""
        # Skip resources that don't support tags
        tags = after.get("tags", {}) or {}
        if not isinstance(tags, dict):
            return

        required_tags = {"owner", "environment"}
        missing = required_tags - set(tags.keys())

        if missing and resource_type.startswith(("aws_", "azurerm_", "google_")):
            warnings.append(
                {
                    "resource": address,
                    "rule": "required_tags",
                    "severity": "low",
                    "message": (
                        f"Resource {address} is missing recommended tags: "
                        f"{', '.join(sorted(missing))}."
                    ),
                }
            )

    # ------------------------------------------------------------------
    # Database query helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _query_frameworks(db: Any) -> list[dict[str, Any]]:
        """Query framework names from the database."""
        try:
            from warlock.db.models import ControlResult

            rows = (
                db.query(ControlResult.framework).distinct().order_by(ControlResult.framework).all()
            )
            return [{"name": row[0]} for row in rows if row[0]]
        except Exception as exc:
            log.warning("Failed to query frameworks: %s", exc)
            return []

    @staticmethod
    def _query_framework_results(db: Any) -> list[dict[str, Any]]:
        """Query control result counts grouped by framework and status."""
        try:
            from sqlalchemy import func

            from warlock.db.models import ControlResult

            rows = (
                db.query(
                    ControlResult.framework,
                    ControlResult.status,
                    func.count(ControlResult.id),
                )
                .group_by(ControlResult.framework, ControlResult.status)
                .all()
            )

            results: dict[str, dict[str, int]] = {}
            for framework, status, count in rows:
                if framework not in results:
                    results[framework] = {}
                results[framework][status or "unknown"] = count

            return [
                {"framework": fw, "statuses": statuses} for fw, statuses in sorted(results.items())
            ]
        except Exception as exc:
            log.warning("Failed to query framework results: %s", exc)
            return []

    @staticmethod
    def _query_findings_summary(db: Any) -> dict[str, Any]:
        """Query open findings count by severity."""
        try:
            from sqlalchemy import func

            from warlock.db.models import Finding

            rows = (
                db.query(
                    Finding.severity,
                    func.count(Finding.id),
                )
                .group_by(Finding.severity)
                .all()
            )

            return {(severity or "unknown"): count for severity, count in rows}
        except Exception as exc:
            log.warning("Failed to query findings summary: %s", exc)
            return {}

    @staticmethod
    def _query_control_results(db: Any, *, framework: str | None = None) -> list[dict[str, Any]]:
        """Query control results, optionally filtered by framework."""
        try:
            from warlock.db.models import ControlResult

            query = db.query(ControlResult)
            if framework:
                query = query.filter(ControlResult.framework == framework)
            query = query.limit(10000)  # bounded query

            results = []
            for cr in query.all():
                results.append(
                    {
                        "id": str(cr.id),
                        "framework": cr.framework,
                        "control_id": cr.control_id,
                        "status": cr.status,
                        "severity": getattr(cr, "severity", None),
                    }
                )
            return results
        except Exception as exc:
            log.warning("Failed to query control results: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Configuration check
    # ------------------------------------------------------------------

    @staticmethod
    def is_configured() -> bool:
        """Return True.

        The Terraform provider operates on local data and does not
        require external credentials.  Always considered available.
        """
        return True
