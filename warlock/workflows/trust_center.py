"""Customer-facing trust center data management.

Item 83: Populate trust_documents from existing attestations/OSCAL exports.
Provide public status page data for compliance certifications.

Uses the TrustDocument model for document management and Attestation
model as the source of certification status.
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from warlock.db.audit import AuditTrail
from warlock.db.models import Attestation, TrustDocument, _uuid
from warlock.utils import ensure_aware

log = logging.getLogger(__name__)

# Certification display labels by framework
_FRAMEWORK_LABELS: dict[str, str] = {
    "soc2": "SOC 2 Type II",
    "iso_27001": "ISO 27001",
    "iso_27701": "ISO 27701",
    "hipaa": "HIPAA",
    "fedramp": "FedRAMP",
    "pci_dss": "PCI DSS v4.0",
    "gdpr": "GDPR",
    "cmmc_l2": "CMMC Level 2",
    "nist_800_53": "NIST 800-53",
    "nist_csf": "NIST CSF 2.0",
}

# Status display mapping
_STATUS_LABELS: dict[str, str] = {
    "approved": "Current",
    "active": "Active",
    "completed": "Certified",
    "expired": "Expired",
    "draft": "In Progress",
    "submitted": "Under Review",
    "reviewed": "Under Review",
}


class TrustCenterManager:
    """Manages trust center content and status data."""

    def get_status(self, session: Session) -> list[dict]:
        """Get public trust center status for all certifications.

        Pulls from attestations (approved = current certification) and
        trust documents (published compliance artifacts).
        """
        # Get latest attestation per framework
        attestations = session.query(Attestation).order_by(Attestation.created_at.desc()).all()

        # Deduplicate: latest per framework
        by_framework: dict[str, Attestation] = {}
        for att in attestations:
            if att.framework not in by_framework:
                by_framework[att.framework] = att

        statuses = []
        for fw, att in sorted(by_framework.items()):
            label = _FRAMEWORK_LABELS.get(fw, fw.upper())
            status_label = _STATUS_LABELS.get(att.status, att.status)
            statuses.append(
                {
                    "framework": fw,
                    "label": label,
                    "status": status_label,
                    "raw_status": att.status,
                    "last_updated": ensure_aware(att.created_at).isoformat()
                    if att.created_at
                    else "",
                    "attestation_id": att.id,
                }
            )

        return statuses

    def list_documents(self, session: Session) -> list[dict]:
        """List published trust center documents."""
        docs = (
            session.query(TrustDocument)
            .filter(TrustDocument.is_active.is_(True))
            .order_by(TrustDocument.uploaded_at.desc())
            .all()
        )

        return [
            {
                "id": d.id,
                "title": d.title,
                "description": d.description or "",
                "classification": d.classification_tier,
                "content_type": d.content_type or "",
                "uploaded_by": d.uploaded_by,
                "uploaded_at": ensure_aware(d.uploaded_at).isoformat() if d.uploaded_at else "",
            }
            for d in docs
        ]

    def publish_document(
        self,
        session: Session,
        *,
        document_id: str,
        actor: str = "system",
    ) -> dict:
        """Publish a trust document (set is_active = True).

        Raises ValueError if the document is not found.
        """
        doc = session.query(TrustDocument).filter(TrustDocument.id == document_id).first()
        if not doc:
            raise ValueError(f"Trust document not found: {document_id}")

        doc.is_active = True

        audit = AuditTrail(session)
        audit.record(
            action="trust_document_published",
            entity_type="trust_document",
            entity_id=document_id,
            actor=actor,
            metadata={"title": doc.title, "classification": doc.classification_tier},
        )

        log.info("Trust document published: %s (%s)", doc.title, document_id)
        return {
            "id": doc.id,
            "title": doc.title,
            "classification": doc.classification_tier,
            "published": True,
        }

    def unpublish_document(
        self,
        session: Session,
        *,
        document_id: str,
        actor: str = "system",
    ) -> dict:
        """Unpublish a trust document (set is_active = False)."""
        doc = session.query(TrustDocument).filter(TrustDocument.id == document_id).first()
        if not doc:
            raise ValueError(f"Trust document not found: {document_id}")

        doc.is_active = False

        audit = AuditTrail(session)
        audit.record(
            action="trust_document_unpublished",
            entity_type="trust_document",
            entity_id=document_id,
            actor=actor,
            metadata={"title": doc.title},
        )

        return {
            "id": doc.id,
            "title": doc.title,
            "published": False,
        }

    def sync_from_attestations(
        self,
        session: Session,
        *,
        actor: str = "system",
    ) -> dict:
        """Sync trust center status from approved attestations.

        Creates trust documents for approved attestations that don't
        already have a corresponding document.
        """
        approved = session.query(Attestation).filter(Attestation.status == "approved").all()

        created = 0
        skipped = 0
        for att in approved:
            # Check if a trust document already exists for this attestation
            existing = (
                session.query(TrustDocument)
                .filter(
                    TrustDocument.title.contains(att.framework),
                    TrustDocument.is_active.is_(True),
                )
                .first()
            )
            if existing:
                skipped += 1
                continue

            label = _FRAMEWORK_LABELS.get(att.framework, att.framework.upper())
            doc = TrustDocument(
                id=_uuid(),
                title=f"{label} Attestation",
                description=att.statement[:200] if att.statement else "",
                classification_tier="nda",
                file_path=f"attestations/{att.id}.json",
                content_type="application/json",
                uploaded_by=actor,
                is_active=True,
            )
            session.add(doc)
            created += 1

        return {
            "attestations_found": len(approved),
            "documents_created": created,
            "documents_skipped": skipped,
        }
