"""Attestation workflow engine.

Manages the attestation lifecycle (draft -> submitted -> reviewed -> approved/rejected)
with separation-of-duties enforcement and batch preparation from framework definitions.

This module provides ``AttestationWorkflow``, a higher-level orchestration layer
that delegates core state transitions to ``AttestationManager`` from
``warlock.workflows.attestations`` and adds batch-preparation capabilities
driven by the framework YAML control catalogs.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

import yaml
from sqlalchemy.orm import Session

from warlock.db.models import Attestation
from warlock.workflows.attestations import AttestationManager

log = logging.getLogger(__name__)

# Path to framework YAML definitions
_FRAMEWORKS_DIR = Path(__file__).resolve().parent.parent / "frameworks"


class AttestationWorkflow:
    """Manages the attestation lifecycle: prepare -> submit -> review -> approve/reject.

    Wraps ``AttestationManager`` for individual transitions and adds batch
    operations for engagement-level attestation preparation.
    """

    VALID_TRANSITIONS: dict[str, list[str]] = {
        "draft": ["submitted"],
        "submitted": ["reviewed"],
        "reviewed": ["approved", "rejected"],
        "approved": [],  # terminal
        "rejected": ["draft"],  # can re-draft
    }

    def __init__(self) -> None:
        self._manager = AttestationManager()

    # ------------------------------------------------------------------
    # Individual transitions
    # ------------------------------------------------------------------

    def submit(
        self,
        session: Session,
        attestation_id: str,
        submitted_by: str,
    ) -> Attestation:
        """Submit an attestation for review.

        Validates that the attestation is in ``draft`` status before
        transitioning to ``submitted``.

        Args:
            session: Active SQLAlchemy session.
            attestation_id: UUID of the attestation.
            submitted_by: Actor performing the submission.

        Returns:
            Updated ``Attestation`` instance.

        Raises:
            ValueError: If the attestation is not found or the transition
                is invalid.
        """
        att = self._get_or_raise(session, attestation_id)
        self._validate_transition(att.status, "submitted")
        return self._manager.submit(session, attestation_id, submitted_by)

    def review(
        self,
        session: Session,
        attestation_id: str,
        reviewed_by: str,
        review_notes: str | None = None,
    ) -> Attestation:
        """Mark an attestation as reviewed.

        Enforces separation of duties: the reviewer must differ from the
        preparer.

        Args:
            session: Active SQLAlchemy session.
            attestation_id: UUID of the attestation.
            reviewed_by: Actor performing the review.
            review_notes: Optional reviewer commentary.

        Returns:
            Updated ``Attestation`` instance.

        Raises:
            ValueError: If the attestation is not found, the transition
                is invalid, or separation of duties is violated.
        """
        att = self._get_or_raise(session, attestation_id)
        self._validate_transition(att.status, "reviewed")
        return self._manager.review(session, attestation_id, reviewed_by, notes=review_notes)

    def approve(
        self,
        session: Session,
        attestation_id: str,
        approved_by: str,
    ) -> Attestation:
        """Approve an attestation.

        Enforces separation of duties: the approver must differ from both
        the preparer and the submitter.

        Args:
            session: Active SQLAlchemy session.
            attestation_id: UUID of the attestation.
            approved_by: Actor granting approval.

        Returns:
            Updated ``Attestation`` instance.

        Raises:
            ValueError: If the attestation is not found, the transition
                is invalid, or separation of duties is violated.
        """
        att = self._get_or_raise(session, attestation_id)
        self._validate_transition(att.status, "approved")
        return self._manager.approve(session, attestation_id, approved_by)

    def reject(
        self,
        session: Session,
        attestation_id: str,
        rejected_by: str,
        reason: str,
    ) -> Attestation:
        """Reject an attestation back to draft.

        Args:
            session: Active SQLAlchemy session.
            attestation_id: UUID of the attestation.
            rejected_by: Actor rejecting the attestation.
            reason: Mandatory explanation for the rejection.

        Returns:
            Updated ``Attestation`` instance.

        Raises:
            ValueError: If the attestation is not found or the transition
                is invalid.
        """
        att = self._get_or_raise(session, attestation_id)
        # reject is allowed from submitted or reviewed
        if att.status not in ("submitted", "reviewed"):
            raise ValueError(
                f"Cannot reject from status '{att.status}'. "
                f"Rejection is allowed from 'submitted' or 'reviewed'."
            )
        return self._manager.reject(session, attestation_id, rejected_by, reason)

    # ------------------------------------------------------------------
    # Batch preparation
    # ------------------------------------------------------------------

    def prepare_batch(
        self,
        session: Session,
        framework: str,
        engagement_id: str,
        prepared_by: str = "system",
    ) -> list[Attestation]:
        """Auto-create draft attestations for every control in a framework.

        Loads the framework YAML to enumerate all controls, then creates
        one ``Attestation`` per control in ``draft`` status.  Existing
        attestations for the same (engagement, framework, control) tuple
        are skipped to avoid duplicates.

        Args:
            session: Active SQLAlchemy session.
            framework: Framework identifier (e.g. ``soc2``, ``nist_800_53``).
            engagement_id: UUID of the audit engagement to bind to.
            prepared_by: Actor creating the drafts (default ``"system"``).

        Returns:
            List of newly created ``Attestation`` instances.

        Raises:
            FileNotFoundError: If the framework YAML cannot be found.
            ValueError: If the YAML has no parseable controls.
        """
        controls = self._load_framework_controls(framework)
        if not controls:
            raise ValueError(f"No controls found for framework '{framework}'")

        # Determine which controls already have an attestation for this engagement
        existing = (
            session.query(Attestation.control_id)
            .filter(
                Attestation.engagement_id == engagement_id,
                Attestation.framework == framework,
            )
            .all()
        )
        existing_ids: set[str] = {row[0] for row in existing if row[0]}

        now = datetime.now(timezone.utc)
        created: list[Attestation] = []

        for control_id in controls:
            if control_id in existing_ids:
                log.debug(
                    "Skipping %s/%s -- attestation already exists for engagement %s",
                    framework,
                    control_id,
                    engagement_id,
                )
                continue

            att = Attestation(
                engagement_id=engagement_id,
                framework=framework,
                control_id=control_id,
                status="draft",
                statement=f"Management asserts compliance with {framework.upper()} control {control_id}.",
                prepared_by=prepared_by,
                prepared_at=now,
            )
            session.add(att)
            created.append(att)

        session.flush()
        log.info(
            "Prepared %d draft attestations for %s (engagement %s, %d skipped)",
            len(created),
            framework,
            engagement_id,
            len(existing_ids),
        )
        return created

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_or_raise(self, session: Session, attestation_id: str) -> Attestation:
        """Fetch an attestation by ID or prefix, raising on miss."""
        att = session.query(Attestation).filter(Attestation.id.startswith(attestation_id)).first()
        if not att:
            raise ValueError(f"Attestation not found: {attestation_id}")
        return att

    def _validate_transition(self, current: str, target: str) -> None:
        """Validate that a status transition is allowed."""
        allowed = self.VALID_TRANSITIONS.get(current, [])
        if target not in allowed:
            raise ValueError(
                f"Cannot transition from '{current}' to '{target}'. "
                f"Allowed transitions from '{current}': {allowed}"
            )

    @staticmethod
    def _load_framework_controls(framework: str) -> list[str]:
        """Load control IDs from a framework YAML.

        Returns a flat list of control IDs (e.g. ``["CC1.1", "CC1.2", ...]``).
        """
        yaml_path = _FRAMEWORKS_DIR / f"{framework}.yaml"
        if not yaml_path.exists():
            raise FileNotFoundError(f"Framework YAML not found: {yaml_path}")

        with open(yaml_path) as fh:
            data = yaml.safe_load(fh)

        controls: list[str] = []
        families = data.get("control_families", {})
        for _family_id, family in families.items():
            family_controls = family.get("controls", {})
            for control_id in family_controls:
                controls.append(control_id)

        return controls
