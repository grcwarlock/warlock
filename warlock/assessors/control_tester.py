"""Active control testing automation (#59).

Unlike passive assertion checks that evaluate individual findings, these tests
actively query the database for conditions that indicate a control *failure*.
Each test targets a specific control domain and returns structured results
suitable for compliance dashboards and audit evidence.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from warlock.db.models import (
    ChangeEvent,
    DataSilo,
    Finding,
    Personnel,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result data class
# ---------------------------------------------------------------------------


@dataclass
class ControlTestResult:
    """Outcome of a single control test."""

    control_id: str
    test_name: str
    passed: bool
    details: list[str] = field(default_factory=list)
    tested_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Sensitive ports for network segmentation test
# ---------------------------------------------------------------------------

_SENSITIVE_PORTS: set[int] = {22, 3389, 5432, 3306, 1433, 6379, 27017, 9200}


# ---------------------------------------------------------------------------
# ControlTester
# ---------------------------------------------------------------------------


class ControlTester:
    """Active control validation engine.

    Each ``test_*`` method queries the database for a condition that would
    constitute a control failure and returns a :class:`ControlTestResult`.
    """

    # -- AC: Access Control ------------------------------------------------

    @staticmethod
    def test_access_control(session: Session) -> ControlTestResult:
        """AC-2 / CC6.1: Verify terminated employees cannot authenticate.

        Queries Personnel where ``hr_status='terminated'`` but
        ``idp_status='active'`` -- a condition that means a terminated
        person still has live IdP credentials.
        """
        violations = (
            session.query(Personnel)
            .filter(
                Personnel.hr_status == "terminated",
                Personnel.idp_status == "active",
            )
            .all()
        )

        details = [
            f"Terminated employee still active in IdP: "
            f"{v.full_name} ({v.email}), "
            f"terminated {v.termination_date.date() if v.termination_date else 'unknown'}, "
            f"idp_provider={v.idp_provider or 'unknown'}"
            for v in violations
        ]

        passed = len(violations) == 0
        if not passed:
            log.warning(
                "AC-2 control test FAILED: %d terminated employees with active IdP accounts",
                len(violations),
            )

        return ControlTestResult(
            control_id="AC-2",
            test_name="terminated_employee_access",
            passed=passed,
            details=details,
        )

    # -- SC: System and Communications Protection --------------------------

    @staticmethod
    def test_encryption(session: Session) -> ControlTestResult:
        """SC-28 / CC6.1: Verify data silos with PII/PHI/PCI are encrypted at rest.

        Any DataSilo containing sensitive data (PII, PHI, or PCI) that does
        *not* have ``encrypted_at_rest=True`` is a control failure.
        """
        from sqlalchemy import or_

        unencrypted = (
            session.query(DataSilo)
            .filter(
                or_(
                    DataSilo.contains_pii == True,  # noqa: E712
                    DataSilo.contains_phi == True,  # noqa: E712
                    DataSilo.contains_pci == True,  # noqa: E712
                ),
                or_(
                    DataSilo.encrypted_at_rest == False,  # noqa: E712
                    DataSilo.encrypted_at_rest == None,  # noqa: E711
                ),
            )
            .all()
        )

        details = []
        for silo in unencrypted:
            data_types = []
            if silo.contains_pii:
                data_types.append("PII")
            if silo.contains_phi:
                data_types.append("PHI")
            if silo.contains_pci:
                data_types.append("PCI")
            details.append(
                f"Unencrypted {silo.silo_type} '{silo.name}' "
                f"contains {', '.join(data_types)}, "
                f"provider={silo.provider or 'unknown'}"
            )

        passed = len(unencrypted) == 0
        if not passed:
            log.warning(
                "SC-28 control test FAILED: %d sensitive data silos without encryption",
                len(unencrypted),
            )

        return ControlTestResult(
            control_id="SC-28",
            test_name="sensitive_data_encryption",
            passed=passed,
            details=details,
        )

    # -- CP: Contingency Planning ------------------------------------------

    @staticmethod
    def test_backup_recovery(session: Session) -> ControlTestResult:
        """CP-9 / A.12.3.1: Verify backup jobs have recent successful runs.

        Looks at DataSilo records where ``backup_enabled=True`` and checks
        for corresponding findings (from Veeam, AWS Backup, etc.) that
        confirm a recent successful backup within the last 7 days.  Silos
        with no recent successful backup finding are flagged.
        """
        now = datetime.now(timezone.utc)
        seven_days_ago = now - timedelta(days=7)

        backup_silos = (
            session.query(DataSilo)
            .filter(DataSilo.backup_enabled == True)  # noqa: E712
            .all()
        )

        details: list[str] = []
        for silo in backup_silos:
            # Look for a recent backup-related finding for this silo
            recent_backup = (
                session.query(Finding)
                .filter(
                    Finding.resource_name == silo.name,
                    Finding.observation_type == "inventory",
                    Finding.observed_at >= seven_days_ago,
                    Finding.title.ilike("%backup%"),
                )
                .first()
            )
            if not recent_backup:
                details.append(
                    f"No recent backup evidence for '{silo.name}' "
                    f"({silo.silo_type}, provider={silo.provider or 'unknown'})"
                )

        passed = len(details) == 0
        if not passed:
            log.warning(
                "CP-9 control test FAILED: %d backup-enabled silos without recent backup evidence",
                len(details),
            )

        return ControlTestResult(
            control_id="CP-9",
            test_name="backup_recovery_verification",
            passed=passed,
            details=details,
        )

    # -- SC: Network Segmentation ------------------------------------------

    @staticmethod
    def test_network_segmentation(session: Session) -> ControlTestResult:
        """SC-7 / CC6.6: Verify no security groups allow 0.0.0.0/0 on sensitive ports.

        Queries findings from cloud security group scans for rules that
        permit unrestricted inbound access (``0.0.0.0/0`` or ``::/0``) on
        ports commonly associated with administrative or database services.
        """
        sg_findings = (
            session.query(Finding)
            .filter(
                Finding.observation_type == "misconfiguration",
                Finding.resource_type.in_(["ec2_security_group", "security_group", "nsg"]),
            )
            .all()
        )

        details: list[str] = []
        for f in sg_findings:
            detail = f.detail if isinstance(f.detail, dict) else {}
            rules = detail.get("ingress_rules", detail.get("rules", []))
            if not isinstance(rules, list):
                continue
            for rule in rules:
                cidr = rule.get("cidr", rule.get("cidr_block", ""))
                port = rule.get("port", rule.get("from_port"))
                if cidr in ("0.0.0.0/0", "::/0") and port in _SENSITIVE_PORTS:
                    details.append(
                        f"Security group '{f.resource_name or f.resource_id}' "
                        f"allows {cidr} on port {port}"
                    )

        passed = len(details) == 0
        if not passed:
            log.warning(
                "SC-7 control test FAILED: %d overly-permissive security group rules found",
                len(details),
            )

        return ControlTestResult(
            control_id="SC-7",
            test_name="network_segmentation",
            passed=passed,
            details=details,
        )

    # -- CM: Configuration Management / Change Control ---------------------

    @staticmethod
    def test_change_management(session: Session) -> ControlTestResult:
        """CM-3 / CC8.1: Verify recent changes have approved change requests.

        Looks at ChangeEvent records from the last 30 days and checks
        whether each has an associated approved change request (detail
        contains ``change_request_id`` and ``approved=True``).  Changes
        without approval metadata are flagged.
        """
        now = datetime.now(timezone.utc)
        thirty_days_ago = now - timedelta(days=30)

        recent_changes = (
            session.query(ChangeEvent).filter(ChangeEvent.occurred_at >= thirty_days_ago).all()
        )

        details: list[str] = []
        for change in recent_changes:
            detail = change.detail if isinstance(change.detail, dict) else {}
            cr_id = detail.get("change_request_id")
            approved = detail.get("approved", False)
            if not cr_id or not approved:
                details.append(
                    f"Unapproved change: {change.action} on "
                    f"{change.resource_type or 'unknown'}/"
                    f"{change.resource_id or 'unknown'} "
                    f"by {change.actor or 'unknown'} "
                    f"at {change.occurred_at.isoformat()}"
                )

        passed = len(details) == 0
        if not passed:
            log.warning(
                "CM-3 control test FAILED: %d changes without approved change requests",
                len(details),
            )

        return ControlTestResult(
            control_id="CM-3",
            test_name="change_management_approval",
            passed=passed,
            details=details,
        )

    # -- Run all tests -----------------------------------------------------

    def run_all_tests(self, session: Session) -> list[ControlTestResult]:
        """Execute all control tests and return a list of results."""
        results = [
            self.test_access_control(session),
            self.test_encryption(session),
            self.test_backup_recovery(session),
            self.test_network_segmentation(session),
            self.test_change_management(session),
        ]

        passed = sum(1 for r in results if r.passed)
        failed = len(results) - passed
        log.info(
            "Control test suite complete: %d passed, %d failed out of %d tests",
            passed,
            failed,
            len(results),
        )

        return results
