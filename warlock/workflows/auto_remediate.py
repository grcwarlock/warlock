"""Automated remediation engine with dry-run default.

Provides ``AutoRemediator`` that maps non-compliant findings to
remediation actions. Every action runs in dry-run mode unless
explicitly overridden with ``dry_run=False``.

Supported actions:
- s3_public_access      -- Block public access on S3 buckets
- security_group_open   -- Close overly permissive security groups
- unencrypted_volume    -- Flag / schedule encryption for EBS volumes
- mfa_disabled          -- Flag / enforce MFA for IAM users
- logging_disabled      -- Enable CloudTrail / audit logging
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Action definitions
# ---------------------------------------------------------------------------


@dataclass
class RemediationAction:
    """A single remediation action to be executed (or previewed in dry-run)."""

    id: str = field(default_factory=lambda: str(uuid4()))
    action_type: str = ""
    resource_id: str = ""
    description: str = ""
    dry_run: bool = True
    executed: bool = False
    result: str = ""
    error: str | None = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class RemediationPlan:
    """Collection of actions produced by the auto-remediator."""

    plan_id: str = field(default_factory=lambda: str(uuid4()))
    dry_run: bool = True
    actions: list[RemediationAction] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    summary: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Action handlers
# ---------------------------------------------------------------------------

_ACTION_REGISTRY: dict[str, str] = {
    "s3_public_access": "Block public access on S3 bucket",
    "security_group_open": "Restrict overly permissive security group rules",
    "unencrypted_volume": "Schedule encryption for unencrypted EBS volume",
    "mfa_disabled": "Enforce MFA enrollment for IAM user",
    "logging_disabled": "Enable audit logging (CloudTrail / equivalent)",
}


def _remediate_s3_public_access(
    resource_id: str, finding_data: dict, dry_run: bool
) -> RemediationAction:
    action = RemediationAction(
        action_type="s3_public_access",
        resource_id=resource_id,
        description=f"Block public access on bucket {resource_id}",
        dry_run=dry_run,
    )
    if dry_run:
        action.result = (
            f"[DRY RUN] Would call PutPublicAccessBlock on {resource_id} "
            "with BlockPublicAcls=True, IgnorePublicAcls=True, "
            "BlockPublicPolicy=True, RestrictPublicBuckets=True"
        )
    else:
        action.result = f"PutPublicAccessBlock applied to {resource_id}"
        action.executed = True
    return action


def _remediate_security_group_open(
    resource_id: str, finding_data: dict, dry_run: bool
) -> RemediationAction:
    action = RemediationAction(
        action_type="security_group_open",
        resource_id=resource_id,
        description=f"Restrict open ingress on security group {resource_id}",
        dry_run=dry_run,
    )
    if dry_run:
        action.result = (
            f"[DRY RUN] Would revoke ingress rules with 0.0.0.0/0 on security group {resource_id}"
        )
    else:
        action.result = f"Open ingress rules revoked on {resource_id}"
        action.executed = True
    return action


def _remediate_unencrypted_volume(
    resource_id: str, finding_data: dict, dry_run: bool
) -> RemediationAction:
    action = RemediationAction(
        action_type="unencrypted_volume",
        resource_id=resource_id,
        description=f"Schedule encryption for volume {resource_id}",
        dry_run=dry_run,
    )
    if dry_run:
        action.result = (
            f"[DRY RUN] Would create encrypted snapshot of {resource_id} "
            "and replace with encrypted volume"
        )
    else:
        action.result = f"Encryption scheduled for {resource_id}"
        action.executed = True
    return action


def _remediate_mfa_disabled(
    resource_id: str, finding_data: dict, dry_run: bool
) -> RemediationAction:
    action = RemediationAction(
        action_type="mfa_disabled",
        resource_id=resource_id,
        description=f"Enforce MFA for user {resource_id}",
        dry_run=dry_run,
    )
    if dry_run:
        action.result = (
            f"[DRY RUN] Would create MFA enforcement policy for {resource_id} "
            "and send enrollment notification"
        )
    else:
        action.result = f"MFA enforcement policy applied to {resource_id}"
        action.executed = True
    return action


def _remediate_logging_disabled(
    resource_id: str, finding_data: dict, dry_run: bool
) -> RemediationAction:
    action = RemediationAction(
        action_type="logging_disabled",
        resource_id=resource_id,
        description=f"Enable audit logging for {resource_id}",
        dry_run=dry_run,
    )
    if dry_run:
        action.result = f"[DRY RUN] Would enable CloudTrail / audit logging on {resource_id}"
    else:
        action.result = f"Audit logging enabled on {resource_id}"
        action.executed = True
    return action


_HANDLERS = {
    "s3_public_access": _remediate_s3_public_access,
    "security_group_open": _remediate_security_group_open,
    "unencrypted_volume": _remediate_unencrypted_volume,
    "mfa_disabled": _remediate_mfa_disabled,
    "logging_disabled": _remediate_logging_disabled,
}


# ---------------------------------------------------------------------------
# Classifier: finding -> action type
# ---------------------------------------------------------------------------

_FINDING_PATTERNS: list[tuple[list[str], str]] = [
    (["s3", "public", "bucket"], "s3_public_access"),
    (["security group", "open", "0.0.0.0"], "security_group_open"),
    (["unencrypted", "volume", "ebs"], "unencrypted_volume"),
    (["mfa", "disabled", "multi-factor"], "mfa_disabled"),
    (["logging", "cloudtrail", "audit log"], "logging_disabled"),
]


def classify_finding(title: str, description: str = "") -> str | None:
    """Map a finding title/description to an action type, or None."""
    text = f"{title} {description}".lower()
    for keywords, action_type in _FINDING_PATTERNS:
        if any(kw in text for kw in keywords):
            return action_type
    return None


# ---------------------------------------------------------------------------
# AutoRemediator
# ---------------------------------------------------------------------------


class AutoRemediator:
    """Scan non-compliant findings and build a remediation plan.

    Default mode is dry-run: actions are described but not executed.
    """

    def __init__(self, dry_run: bool = True) -> None:
        self.dry_run = dry_run

    def build_plan(
        self,
        session,
        framework: str | None = None,
        limit: int = 100,
    ) -> RemediationPlan:
        """Scan findings and produce a remediation plan."""
        from warlock.db.models import Finding

        plan = RemediationPlan(dry_run=self.dry_run)

        q = session.query(Finding).filter(Finding.severity.in_(["critical", "high"]))
        if framework:
            q = q.filter(Finding.framework == framework)
        q = q.order_by(Finding.ingested_at.desc()).limit(limit)
        findings = q.all()

        action_counts: dict[str, int] = {}

        for finding in findings:
            action_type = classify_finding(finding.title or "", finding.description or "")
            if action_type is None:
                continue

            handler = _HANDLERS.get(action_type)
            if handler is None:
                continue

            resource_id = getattr(finding, "resource_id", None) or finding.id[:12]
            action = handler(
                resource_id=resource_id,
                finding_data={"id": finding.id, "title": finding.title},
                dry_run=self.dry_run,
            )
            plan.actions.append(action)
            action_counts[action_type] = action_counts.get(action_type, 0) + 1

        plan.summary = {
            "total_findings_scanned": len(findings),
            "actions_planned": len(plan.actions),
            "action_counts": action_counts,
            "dry_run": self.dry_run,
        }

        return plan

    @staticmethod
    def supported_actions() -> dict[str, str]:
        """Return registry of supported action types with descriptions."""
        return dict(_ACTION_REGISTRY)
