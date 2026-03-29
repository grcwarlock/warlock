"""Questionnaire auto-fill from evidence corpus.

Given a questionnaire template (JSON with questions), searches the evidence
corpus and pre-fills answers based on matching control results, findings,
attestations, and policy documents.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from warlock.db.models import (
    Attestation,
    ControlResult,
)

log = logging.getLogger(__name__)


@dataclass
class QuestionAnswer:
    """A single question with auto-filled answer."""

    question_id: str = ""
    question_text: str = ""
    answer: str = ""
    confidence: float = 0.0  # 0.0-1.0
    evidence_refs: list[str] = field(default_factory=list)
    source: str = ""  # "control_result", "attestation", "evidence", "not_found"


@dataclass
class AutofillResult:
    """Result of questionnaire auto-fill."""

    total_questions: int = 0
    answered: int = 0
    high_confidence: int = 0  # confidence >= 0.8
    low_confidence: int = 0  # confidence < 0.5
    not_found: int = 0
    answers: list[QuestionAnswer] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Keyword-to-control mapping for common questionnaire domains
# ---------------------------------------------------------------------------

_KEYWORD_CONTROLS = {
    "encryption": ["SC-28", "SC-13", "sc-28", "sc-13", "CC6.1", "cc6-1"],
    "access control": ["AC-2", "AC-3", "ac-2", "ac-3", "CC6.1", "CC6.3"],
    "mfa": ["IA-2", "ia-2", "CC6.1"],
    "multi-factor": ["IA-2", "ia-2", "CC6.1"],
    "logging": ["AU-2", "AU-3", "au-2", "au-3", "CC7.2"],
    "audit": ["AU-2", "AU-6", "au-2", "au-6", "CC7.2"],
    "incident": ["IR-4", "IR-5", "ir-4", "ir-5", "CC7.3", "CC7.4"],
    "backup": ["CP-9", "CP-10", "cp-9", "cp-10", "A1.2"],
    "vulnerability": ["RA-5", "SI-2", "ra-5", "si-2", "CC7.1"],
    "patch": ["SI-2", "si-2", "CC7.1"],
    "password": ["IA-5", "ia-5", "CC6.1"],
    "network": ["SC-7", "sc-7", "CC6.6"],
    "firewall": ["SC-7", "sc-7", "CC6.6"],
    "training": ["AT-2", "AT-3", "at-2", "at-3", "CC1.4"],
    "privacy": ["PT-1", "pt-1", "P1.0"],
    "data retention": ["SI-12", "si-12", "P4.0"],
    "change management": ["CM-3", "CM-4", "cm-3", "cm-4", "CC8.1"],
    "risk assessment": ["RA-3", "ra-3", "CC3.2"],
    "penetration test": ["CA-8", "ca-8", "CC4.1"],
    "disaster recovery": ["CP-2", "CP-10", "cp-2", "cp-10", "A1.2"],
    "soc 2": ["CC1.1", "CC2.1", "CC3.1"],
    "gdpr": ["PT-1", "pt-1", "Article 5", "Article 32"],
}


def _match_keywords(text: str) -> list[str]:
    """Find control IDs relevant to a question text."""
    text_lower = text.lower()
    matched: list[str] = []
    for keyword, controls in _KEYWORD_CONTROLS.items():
        if keyword in text_lower:
            matched.extend(controls)
    return list(set(matched))


def autofill_questionnaire(
    session: Session,
    questions: list[dict[str, Any]],
    framework: str | None = None,
) -> AutofillResult:
    """Auto-fill a questionnaire from the evidence corpus.

    Parameters
    ----------
    session: SQLAlchemy session
    questions: list of dicts with at minimum ``id`` and ``text`` keys
    framework: optional framework filter for control results
    """
    result = AutofillResult(total_questions=len(questions))

    for q in questions:
        qa = QuestionAnswer(
            question_id=q.get("id", ""),
            question_text=q.get("text", ""),
        )

        # Find relevant controls based on question text
        control_ids = _match_keywords(qa.question_text)

        if control_ids:
            # Look for compliant control results
            crq = session.query(ControlResult).filter(
                ControlResult.control_id.in_(control_ids),
            )
            if framework:
                crq = crq.filter(ControlResult.framework == framework)
            cr_rows = crq.all()

            compliant = [r for r in cr_rows if r.status == "compliant"]
            if compliant:
                cr = compliant[0]
                qa.answer = (
                    f"Yes. Control {cr.control_id} ({cr.framework}) is assessed as "
                    f"compliant. Assessment method: {cr.assessor or 'automated'}."
                )
                qa.confidence = 0.85
                qa.source = "control_result"
                qa.evidence_refs.append(f"control_result:{cr.id[:8]}")
            elif cr_rows:
                cr = cr_rows[0]
                qa.answer = (
                    f"Partially implemented. Control {cr.control_id} ({cr.framework}) "
                    f"is currently assessed as {cr.status}."
                )
                qa.confidence = 0.5
                qa.source = "control_result"
                qa.evidence_refs.append(f"control_result:{cr.id[:8]}")

        # Fall back to attestation search
        if not qa.answer:
            att_q = (
                session.query(Attestation)
                .filter(
                    Attestation.status == "current",
                )
                .limit(5)
            )
            for att in att_q.all():
                att_text = (att.scope or "") + " " + (att.notes or "")
                if any(kw in att_text.lower() for kw in _match_keywords(qa.question_text)):
                    qa.answer = (
                        f"Attested. See attestation {att.id[:8]} ({att.framework or 'general'})."
                    )
                    qa.confidence = 0.6
                    qa.source = "attestation"
                    qa.evidence_refs.append(f"attestation:{att.id[:8]}")
                    break

        if not qa.answer:
            qa.source = "not_found"
            qa.answer = ""
            qa.confidence = 0.0
            result.not_found += 1
        else:
            result.answered += 1
            if qa.confidence >= 0.8:
                result.high_confidence += 1
            elif qa.confidence < 0.5:
                result.low_confidence += 1

        result.answers.append(qa)

    return result
