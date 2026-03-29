"""Guided Remediation Wizard.

For a given finding, generates step-by-step remediation guidance:
  1. Describe the issue (from finding data)
  2. Show affected controls
  3. Provide fix steps (from remediation KB templates)
  4. Link to resource (construct cloud console URL)
  5. Verify step (re-run relevant assertion)
  6. Mark complete
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from warlock.db.audit import AuditTrail
from warlock.db.models import ControlMapping, ControlResult, Finding, Remediation
from warlock.utils import ensure_aware

log = logging.getLogger(__name__)

# Cloud console URL templates by provider/resource type
_CONSOLE_URLS: dict[str, str] = {
    "aws:ec2_instance": "https://console.aws.amazon.com/ec2/home?region={region}#Instances:instanceId={resource_id}",
    "aws:s3_bucket": "https://s3.console.aws.amazon.com/s3/buckets/{resource_name}",
    "aws:iam_user": "https://console.aws.amazon.com/iam/home#/users/{resource_name}",
    "aws:iam_role": "https://console.aws.amazon.com/iam/home#/roles/{resource_name}",
    "aws:rds_instance": "https://console.aws.amazon.com/rds/home?region={region}#database:id={resource_name}",
    "aws:lambda_function": "https://console.aws.amazon.com/lambda/home?region={region}#/functions/{resource_name}",
    "aws:kms_key": "https://console.aws.amazon.com/kms/home?region={region}#/kms/keys/{resource_id}",
    "aws:security_group": "https://console.aws.amazon.com/ec2/home?region={region}#SecurityGroup:groupId={resource_id}",
    "azure:virtual_machine": "https://portal.azure.com/#resource{resource_id}",
    "azure:storage_account": "https://portal.azure.com/#resource{resource_id}",
    "azure:key_vault": "https://portal.azure.com/#resource{resource_id}",
    "gcp:compute_instance": "https://console.cloud.google.com/compute/instancesDetail/zones/{region}/instances/{resource_name}",
    "gcp:storage_bucket": "https://console.cloud.google.com/storage/browser/{resource_name}",
}


class RemediationWizard:
    """Generates step-by-step remediation guidance for findings."""

    # ------------------------------------------------------------------
    # Generate wizard steps
    # ------------------------------------------------------------------

    def generate_steps(
        self,
        session: Session,
        finding_id: str,
    ) -> dict:
        """Generate a complete remediation wizard for a finding.

        Args:
            session: SQLAlchemy session.
            finding_id: Finding UUID (or prefix).

        Returns:
            Dict with steps: issue_description, affected_controls,
            fix_steps, resource_link, verify_info.

        Raises:
            ValueError: If finding not found.
        """
        finding = self._resolve_finding(session, finding_id)

        # Step 1: Describe the issue
        issue = self._describe_issue(finding)

        # Step 2: Affected controls
        controls = self._get_affected_controls(session, finding)

        # Step 3: Fix steps from KB
        fix_steps = self._get_fix_steps(controls)

        # Step 4: Resource link
        resource_link = self._build_resource_link(finding)

        # Step 5: Verify info
        verify_info = self._get_verify_info(controls)

        return {
            "finding_id": finding.id,
            "finding_title": finding.title,
            "steps": [
                {
                    "step": 1,
                    "title": "Issue Description",
                    "content": issue,
                },
                {
                    "step": 2,
                    "title": "Affected Controls",
                    "content": controls,
                },
                {
                    "step": 3,
                    "title": "Remediation Steps",
                    "content": fix_steps,
                },
                {
                    "step": 4,
                    "title": "Resource Link",
                    "content": resource_link,
                },
                {
                    "step": 5,
                    "title": "Verification",
                    "content": verify_info,
                },
                {
                    "step": 6,
                    "title": "Mark Complete",
                    "content": {
                        "instruction": (
                            "After verifying the fix, mark this remediation "
                            "complete to update tracking."
                        ),
                    },
                },
            ],
        }

    # ------------------------------------------------------------------
    # Mark finding remediation complete
    # ------------------------------------------------------------------

    def mark_complete(
        self,
        session: Session,
        finding_id: str,
        *,
        actor: str = "system",
        notes: str | None = None,
    ) -> dict:
        """Mark a finding's remediation as complete.

        Creates or updates a Remediation record linked to the finding.

        Args:
            session: SQLAlchemy session.
            finding_id: Finding UUID (or prefix).
            actor: Who completed the remediation.
            notes: Completion notes.

        Returns:
            Dict with remediation details.
        """
        finding = self._resolve_finding(session, finding_id)

        # Find existing remediation or create one
        rem = session.query(Remediation).filter(Remediation.finding_id == finding.id).first()

        now = datetime.now(timezone.utc)

        if rem:
            rem.status = "closed"
            rem.closed_at = now
            rem.updated_at = now
            rem.verification_notes = notes or "Completed via remediation wizard"
        else:
            from uuid import uuid4

            rem = Remediation(
                id=str(uuid4()),
                title=f"Remediation: {finding.title[:80]}",
                finding_id=finding.id,
                framework=finding.source,
                status="closed",
                closed_at=now,
                created_at=now,
                updated_at=now,
                created_by=actor,
                verification_notes=notes or "Completed via remediation wizard",
            )
            session.add(rem)

        session.flush()

        audit = AuditTrail(session)
        audit.record(
            action="remediation_wizard_completed",
            entity_type="finding",
            entity_id=finding.id,
            actor=actor,
            metadata={
                "remediation_id": rem.id,
                "finding_title": finding.title[:100],
                "notes": notes,
            },
        )

        log.info("Remediation wizard completed for finding %s", finding.id)
        return {
            "finding_id": finding.id,
            "remediation_id": rem.id,
            "status": "closed",
            "completed_at": now.isoformat(),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_finding(self, session: Session, finding_id: str) -> Finding:
        """Resolve a finding by ID or prefix."""
        finding = session.get(Finding, finding_id)
        if finding:
            return finding
        finding = session.query(Finding).filter(Finding.id.startswith(finding_id)).first()
        if not finding:
            raise ValueError(f"Finding not found: {finding_id}")
        return finding

    def _describe_issue(self, finding: Finding) -> dict:
        """Extract issue description from finding data."""
        detail = finding.detail or {}
        return {
            "title": finding.title,
            "severity": finding.severity,
            "observation_type": finding.observation_type,
            "resource_id": finding.resource_id or "N/A",
            "resource_type": finding.resource_type or "N/A",
            "resource_name": finding.resource_name or "N/A",
            "source": finding.source,
            "provider": finding.provider,
            "description": detail.get("description", finding.title),
            "observed_at": (
                ensure_aware(finding.observed_at).isoformat() if finding.observed_at else "N/A"
            ),
        }

    def _get_affected_controls(
        self,
        session: Session,
        finding: Finding,
    ) -> list[dict]:
        """Get controls affected by this finding."""
        mappings = (
            session.query(ControlMapping).filter(ControlMapping.finding_id == finding.id).all()
        )

        controls = []
        for m in mappings:
            # Get latest result for this control
            result = (
                session.query(ControlResult)
                .filter(
                    ControlResult.framework == m.framework,
                    ControlResult.control_id == m.control_id,
                )
                .order_by(ControlResult.assessed_at.desc())
                .first()
            )

            controls.append(
                {
                    "framework": m.framework,
                    "control_id": m.control_id,
                    "control_family": m.control_family or "",
                    "status": result.status if result else "not_assessed",
                    "severity": result.severity if result else finding.severity,
                    "assertion_name": result.assertion_name if result else None,
                }
            )

        return controls

    def _get_fix_steps(self, controls: list[dict]) -> list[dict]:
        """Get remediation steps from the KB for affected controls."""
        from warlock.assessors.remediation_loader import get_remediation

        steps = []
        seen = set()

        for ctrl in controls:
            key = (ctrl["framework"], ctrl["control_id"])
            if key in seen:
                continue
            seen.add(key)

            guidance = get_remediation(ctrl["framework"], ctrl["control_id"])
            if guidance:
                steps.append(
                    {
                        "framework": ctrl["framework"],
                        "control_id": ctrl["control_id"],
                        "summary": guidance.get("summary", ""),
                        "remediation_steps": guidance.get("remediation_steps", []),
                        "console_path": guidance.get("console_path", ""),
                    }
                )

        if not steps:
            steps.append(
                {
                    "framework": "",
                    "control_id": "",
                    "summary": "No specific remediation guidance found in KB.",
                    "remediation_steps": [
                        "Review the finding details above",
                        "Identify the root cause of the non-compliance",
                        "Implement the necessary fix",
                        "Re-run the pipeline to verify",
                    ],
                    "console_path": "",
                }
            )

        return steps

    def _build_resource_link(self, finding: Finding) -> dict:
        """Construct cloud console URL from finding data."""
        provider = (finding.provider or "").lower()
        resource_type = (finding.resource_type or "").lower()
        key = f"{provider}:{resource_type}"

        template = _CONSOLE_URLS.get(key)
        url = None

        if template:
            try:
                url = template.format(
                    resource_id=finding.resource_id or "",
                    resource_name=finding.resource_name or "",
                    region=finding.region or "us-east-1",
                )
            except (KeyError, IndexError):
                url = None

        return {
            "resource_id": finding.resource_id or "N/A",
            "resource_type": finding.resource_type or "N/A",
            "provider": finding.provider or "N/A",
            "console_url": url or "N/A (no console URL template for this resource type)",
        }

    def _get_verify_info(self, controls: list[dict]) -> dict:
        """Get verification info for affected controls."""
        assertions = []
        for ctrl in controls:
            if ctrl.get("assertion_name"):
                assertions.append(
                    {
                        "framework": ctrl["framework"],
                        "control_id": ctrl["control_id"],
                        "assertion": ctrl["assertion_name"],
                    }
                )

        return {
            "instruction": (
                "Re-run the pipeline to verify the fix: `warlock run --framework <framework>`"
            ),
            "assertions_to_verify": assertions,
            "note": (
                "The relevant assertions will automatically re-evaluate "
                "the control status on the next pipeline run."
            ),
        }
