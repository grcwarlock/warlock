"""GDPR data subject rights implementation.

Handles:
- Right of access (Article 15): export all personal data for a subject
- Right to erasure (Article 17): anonymize PII fields
- Right to rectification (Article 16): update personal data
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from warlock.db.audit import AuditTrail
from warlock.db.models import (
    CompensatingControl,
    Issue,
    IssueComment,
    POAM,
    Personnel,
    Questionnaire,
    RiskAcceptance,
    TrustAccessRequest,
    User,
)

log = logging.getLogger(__name__)

# Fields to anonymize on erasure
_PERSONNEL_PII_FIELDS = [
    "email",
    "full_name",
    "manager_email",
    "hr_employee_id",
    "idp_user_id",
]

_USER_PII_FIELDS = [
    "email",
    "name",
]

_TRUST_PII_FIELDS = [
    "company_name",
    "contact_name",
    "contact_email",
]


def _anonymize_value(field_name: str, record_id: str) -> str:
    """Generate a deterministic anonymized value using HMAC.

    The token is derived from hmac(field_name + record_id, secret) so that
    repeated erasure calls for the same record produce identical output,
    making the operation idempotent.

    H-22: The HMAC secret is read from config (WLK_GDPR_HMAC_SECRET).
    If the secret is not configured, this raises RuntimeError to prevent
    silent use of a weak default.
    """
    from warlock.config import get_settings

    secret = get_settings().gdpr_hmac_secret
    if not secret:
        raise RuntimeError(
            "WLK_GDPR_HMAC_SECRET is not configured. "
            "GDPR anonymization requires a secret of at least 32 characters. "
            "Set WLK_GDPR_HMAC_SECRET in your environment or .env file."
        )
    digest = hmac.new(
        secret.encode(),
        f"{field_name}:{record_id}".encode(),
        hashlib.sha256,
    ).hexdigest()[:8]
    return f"[REDACTED-{digest}]"


class GDPRManager:
    """Handles GDPR data subject rights for the platform's own data."""

    def export_subject_data(self, session: Session, email: str) -> dict[str, Any]:
        """Export all personal data for a data subject (Article 15).

        Searches across Personnel, User, and TrustAccessRequest tables.
        Returns a portable JSON-serializable dict.
        """
        result: dict[str, Any] = {
            "subject_email": email,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "data": {},
        }

        # Audit the export request — use anonymized ID, never the real email
        anon_id = _anonymize_value("email", email)
        audit = AuditTrail(session)
        audit.record(
            action="gdpr_export",
            entity_type="data_subject",
            entity_id=anon_id,
            actor="system",
            metadata={"request_type": "article_15_access"},
        )

        # Personnel records
        personnel = session.query(Personnel).filter(Personnel.email == email).first()
        if personnel:
            result["data"]["personnel"] = {
                "full_name": personnel.full_name,
                "email": personnel.email,
                "department": personnel.department,
                "title": personnel.title,
                "manager_email": personnel.manager_email,
                "employee_type": personnel.employee_type,
                "hr_employee_id": personnel.hr_employee_id,
                "hire_date": personnel.hire_date.isoformat() if personnel.hire_date else None,
                "hr_status": personnel.hr_status,
                "idp_provider": personnel.idp_provider,
                "idp_status": personnel.idp_status,
                "mfa_enabled": personnel.mfa_enabled,
                "training_status": personnel.training_status,
                "last_training_date": personnel.last_training_date.isoformat()
                if personnel.last_training_date
                else None,
            }

        # User account
        user = session.query(User).filter(User.email == email).first()
        if user:
            result["data"]["user_account"] = {
                "email": user.email,
                "name": user.name,
                "role": user.role,
                "is_active": user.is_active,
                "created_at": user.created_at.isoformat() if user.created_at else None,
                "last_login": user.last_login.isoformat() if user.last_login else None,
            }

        # Trust access requests
        trust_requests = (
            session.query(TrustAccessRequest)
            .filter(TrustAccessRequest.contact_email == email)
            .all()
        )
        if trust_requests:
            result["data"]["trust_requests"] = [
                {
                    "company_name": tr.company_name,
                    "contact_name": tr.contact_name,
                    "document_types": tr.document_types,
                    "status": tr.status,
                    "created_at": tr.created_at.isoformat() if tr.created_at else None,
                }
                for tr in trust_requests
            ]

        # Issues (assigned_to, assigned_by, created_by)
        issues = (
            session.query(Issue)
            .filter(
                (Issue.assigned_to == email)
                | (Issue.assigned_by == email)
                | (Issue.created_by == email)
            )
            .all()
        )
        if issues:
            result["data"]["issues"] = [
                {
                    "id": iss.id,
                    "title": getattr(iss, "title", ""),
                    "assigned_to": iss.assigned_to,
                    "assigned_by": iss.assigned_by,
                    "created_by": iss.created_by,
                    "status": getattr(iss, "status", ""),
                    "created_at": iss.created_at.isoformat()
                    if getattr(iss, "created_at", None)
                    else None,
                }
                for iss in issues
            ]

        # Issue comments
        comments = session.query(IssueComment).filter(IssueComment.author == email).all()
        if comments:
            result["data"]["issue_comments"] = [
                {
                    "id": c.id,
                    "issue_id": getattr(c, "issue_id", ""),
                    "author": c.author,
                    "created_at": c.created_at.isoformat()
                    if getattr(c, "created_at", None)
                    else None,
                }
                for c in comments
            ]

        # POA&Ms
        poams = (
            session.query(POAM)
            .filter((POAM.created_by == email) | (POAM.updated_by == email))
            .all()
        )
        if poams:
            result["data"]["poams"] = [
                {
                    "id": p.id,
                    "framework": p.framework,
                    "control_id": p.control_id,
                    "status": p.status,
                    "created_by": p.created_by,
                    "updated_by": p.updated_by,
                }
                for p in poams
            ]

        # Risk acceptances
        ras = (
            session.query(RiskAcceptance)
            .filter((RiskAcceptance.requested_by == email) | (RiskAcceptance.approved_by == email))
            .all()
        )
        if ras:
            result["data"]["risk_acceptances"] = [
                {
                    "id": ra.id,
                    "requested_by": ra.requested_by,
                    "approved_by": ra.approved_by,
                    "status": getattr(ra, "status", ""),
                }
                for ra in ras
            ]

        return result

    def erase_subject_data(
        self,
        session: Session,
        email: str,
        erased_by: str = "system",
    ) -> dict[str, Any]:
        """Anonymize all PII for a data subject (Article 17).

        Does not delete records — anonymizes PII fields to preserve
        referential integrity and audit trail continuity.

        #33 fix: Idempotent — safe to call multiple times for the same email.
        Returns immediately if no records match the email (already erased or
        never existed).
        """
        result: dict[str, Any] = {
            "email": email,
            "erased_at": datetime.now(timezone.utc).isoformat(),
            "affected": {},
            "idempotent": False,
        }

        # Personnel
        personnel = session.query(Personnel).filter(Personnel.email == email).first()
        if personnel:
            for field in _PERSONNEL_PII_FIELDS:
                setattr(personnel, field, _anonymize_value(field, personnel.id))
            personnel.is_active = False
            result["affected"]["personnel"] = personnel.id
            log.info("GDPR erasure: anonymized personnel record %s", personnel.id)

        # User account
        user = session.query(User).filter(User.email == email).first()
        if user:
            for field in _USER_PII_FIELDS:
                setattr(user, field, _anonymize_value(field, user.id))
            user.is_active = False
            result["affected"]["user"] = user.id
            log.info("GDPR erasure: anonymized user account %s", user.id)

        # Trust access requests
        trust_requests = (
            session.query(TrustAccessRequest)
            .filter(TrustAccessRequest.contact_email == email)
            .all()
        )
        if trust_requests:
            for tr in trust_requests:
                for field in _TRUST_PII_FIELDS:
                    setattr(tr, field, _anonymize_value(field, tr.id))
            result["affected"]["trust_requests"] = len(trust_requests)
            log.info("GDPR erasure: anonymized %d trust requests", len(trust_requests))

        # W-3: Cascade anonymization to workflow tables
        # Issues
        issue_fields = ["assigned_to", "assigned_by", "created_by"]
        issues = (
            session.query(Issue)
            .filter(
                (Issue.assigned_to == email)
                | (Issue.assigned_by == email)
                | (Issue.created_by == email)
            )
            .all()
        )
        for iss in issues:
            for fld in issue_fields:
                if getattr(iss, fld, None) == email:
                    setattr(iss, fld, _anonymize_value(fld, iss.id))
        if issues:
            result["affected"]["issues"] = len(issues)
            log.info("GDPR erasure: anonymized %d issue records", len(issues))

        # POA&Ms
        poam_fields = ["created_by", "updated_by"]
        poams = (
            session.query(POAM)
            .filter((POAM.created_by == email) | (POAM.updated_by == email))
            .all()
        )
        for p in poams:
            for fld in poam_fields:
                if getattr(p, fld, None) == email:
                    setattr(p, fld, _anonymize_value(fld, p.id))
        if poams:
            result["affected"]["poams"] = len(poams)
            log.info("GDPR erasure: anonymized %d POAM records", len(poams))

        # Risk Acceptances
        ra_fields = ["requested_by", "approved_by"]
        ras = (
            session.query(RiskAcceptance)
            .filter((RiskAcceptance.requested_by == email) | (RiskAcceptance.approved_by == email))
            .all()
        )
        for ra in ras:
            for fld in ra_fields:
                if getattr(ra, fld, None) == email:
                    setattr(ra, fld, _anonymize_value(fld, ra.id))
        if ras:
            result["affected"]["risk_acceptances"] = len(ras)
            log.info("GDPR erasure: anonymized %d risk acceptance records", len(ras))

        # Compensating Controls
        cc_fields = ["created_by", "approved_by"]
        ccs = (
            session.query(CompensatingControl)
            .filter(
                (CompensatingControl.created_by == email)
                | (CompensatingControl.approved_by == email)
            )
            .all()
        )
        for cc in ccs:
            for fld in cc_fields:
                if getattr(cc, fld, None) == email:
                    setattr(cc, fld, _anonymize_value(fld, cc.id))
        if ccs:
            result["affected"]["compensating_controls"] = len(ccs)
            log.info("GDPR erasure: anonymized %d compensating control records", len(ccs))

        # Questionnaires
        q_fields = ["vendor_contact_email", "created_by"]
        qs = (
            session.query(Questionnaire)
            .filter(
                (Questionnaire.vendor_contact_email == email) | (Questionnaire.created_by == email)
            )
            .all()
        )
        for q in qs:
            for fld in q_fields:
                if getattr(q, fld, None) == email:
                    setattr(q, fld, _anonymize_value(fld, q.id))
        if qs:
            result["affected"]["questionnaires"] = len(qs)
            log.info("GDPR erasure: anonymized %d questionnaire records", len(qs))

        # Issue Comments
        comments = session.query(IssueComment).filter(IssueComment.author == email).all()
        for c in comments:
            c.author = _anonymize_value("author", c.id)
        if comments:
            result["affected"]["issue_comments"] = len(comments)
            log.info("GDPR erasure: anonymized %d issue comment records", len(comments))

        # #33: Mark as idempotent if nothing was found (already erased or never existed)
        if not result["affected"]:
            result["idempotent"] = True
            log.info("GDPR erasure: no records found for %s (already erased or not found)", email)
            return result

        session.flush()

        # Compute anonymized entity_id — never log the real email
        anon_id = _anonymize_value("email", email)
        tables_affected = len(result["affected"])
        fields_anonymized = sum(v if isinstance(v, int) else 1 for v in result["affected"].values())

        audit = AuditTrail(session)
        audit.record(
            action="gdpr_erasure",
            entity_type="data_subject",
            entity_id=anon_id,
            actor=erased_by,
            metadata={
                "tables_affected": tables_affected,
                "fields_anonymized": fields_anonymized,
            },
        )

        log.info("GDPR erasure complete for %s: %s", email, result["affected"])
        return result
