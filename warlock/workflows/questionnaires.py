"""Vendor questionnaire management — templates, lifecycle, scoring, AI suggestions.

#46 additions:
- auto_respond(session, questionnaire_id) — bulk-populate ai_suggested_answers from
  control results + finding evidence via keyword matching.
- suggest_response(session, question_text) — on-demand suggestion for a free-text
  question using the same evidence corpus.

Phase 2 additions:
- ai_respond(session, questionnaire_id) — AI-powered auto-response that calls
  AIService.reason() per question, falling back to keyword matching when AI is off.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from warlock.db.models import (
    ControlResult,
    Finding,
    Questionnaire,
    QuestionnaireTemplate,
)
from warlock.utils import ensure_aware

log = logging.getLogger(__name__)


class QuestionnaireManager:
    """Manages vendor security questionnaire lifecycle."""

    # Built-in SIG Lite core security questions
    SIG_LITE_QUESTIONS = [
        {
            "id": "SL-01", "category": "Information Security Program",
            "text": "Does your organization have a formal information security program?",
            "response_type": "yes_no", "required": True,
            "help_text": "Looking for documented security policies and dedicated security personnel.",
            "mapped_controls": ["NIST AC-1", "SOC2 CC1.1", "ISO A.5.1.1"],
        },
        {
            "id": "SL-02", "category": "Information Security Program",
            "text": "Do you have a dedicated information security team or officer (CISO)?",
            "response_type": "yes_no", "required": True,
            "help_text": "CISO or equivalent security leadership role.",
            "mapped_controls": ["NIST PM-2", "SOC2 CC1.2"],
        },
        {
            "id": "SL-03", "category": "Access Control",
            "text": "Do you enforce multi-factor authentication for all user accounts?",
            "response_type": "yes_no", "required": True,
            "help_text": "MFA on VPN, email, admin consoles, and production systems.",
            "mapped_controls": ["NIST IA-2", "SOC2 CC6.1"],
        },
        {
            "id": "SL-04", "category": "Access Control",
            "text": "Do you perform periodic access reviews (at least quarterly)?",
            "response_type": "yes_no", "required": True,
            "help_text": "Regular review and recertification of user access rights.",
            "mapped_controls": ["NIST AC-2", "SOC2 CC6.2", "ISO A.9.2.5"],
        },
        {
            "id": "SL-05", "category": "Access Control",
            "text": "Is the principle of least privilege enforced across systems?",
            "response_type": "yes_no", "required": True,
            "help_text": "Users receive minimum access needed for their role.",
            "mapped_controls": ["NIST AC-6", "SOC2 CC6.3"],
        },
        {
            "id": "SL-06", "category": "Data Protection",
            "text": "Is data encrypted at rest and in transit?",
            "response_type": "yes_no", "required": True,
            "help_text": "AES-256 at rest, TLS 1.2+ in transit.",
            "mapped_controls": ["NIST SC-8", "NIST SC-28", "SOC2 CC6.1"],
        },
        {
            "id": "SL-07", "category": "Data Protection",
            "text": "Do you have a data classification policy?",
            "response_type": "yes_no", "required": True,
            "help_text": "Formal classification scheme (public, internal, confidential, restricted).",
            "mapped_controls": ["NIST RA-2", "ISO A.8.2.1"],
        },
        {
            "id": "SL-08", "category": "Data Protection",
            "text": "Do you have a data retention and disposal policy?",
            "response_type": "yes_no", "required": True,
            "help_text": "Defined retention periods and secure disposal procedures.",
            "mapped_controls": ["NIST SI-12", "ISO A.8.3.2"],
        },
        {
            "id": "SL-09", "category": "Vulnerability Management",
            "text": "Do you perform regular vulnerability scanning (at least monthly)?",
            "response_type": "yes_no", "required": True,
            "help_text": "Automated scanning of infrastructure and applications.",
            "mapped_controls": ["NIST RA-5", "SOC2 CC7.1"],
        },
        {
            "id": "SL-10", "category": "Vulnerability Management",
            "text": "Do you have a patch management program with defined SLAs?",
            "response_type": "yes_no", "required": True,
            "help_text": "Critical patches within 72 hours, high within 30 days.",
            "mapped_controls": ["NIST SI-2", "SOC2 CC7.1"],
        },
        {
            "id": "SL-11", "category": "Incident Response",
            "text": "Do you have a documented incident response plan?",
            "response_type": "yes_no", "required": True,
            "help_text": "Written IR plan with roles, escalation, and communication procedures.",
            "mapped_controls": ["NIST IR-1", "SOC2 CC7.3", "ISO A.16.1.1"],
        },
        {
            "id": "SL-12", "category": "Incident Response",
            "text": "Do you notify customers of security breaches within 72 hours?",
            "response_type": "yes_no", "required": True,
            "help_text": "Contractual or regulatory breach notification timeline.",
            "mapped_controls": ["NIST IR-6", "SOC2 CC7.4"],
        },
        {
            "id": "SL-13", "category": "Business Continuity",
            "text": "Do you have documented business continuity and disaster recovery plans?",
            "response_type": "yes_no", "required": True,
            "help_text": "BCP/DR plans tested at least annually.",
            "mapped_controls": ["NIST CP-2", "SOC2 A1.2", "ISO A.17.1.1"],
        },
        {
            "id": "SL-14", "category": "Business Continuity",
            "text": "What are your Recovery Time Objective (RTO) and Recovery Point Objective (RPO)?",
            "response_type": "text", "required": True,
            "help_text": "Specify RTO and RPO for critical systems.",
            "mapped_controls": ["NIST CP-10", "SOC2 A1.2"],
        },
        {
            "id": "SL-15", "category": "Third-Party Risk",
            "text": "Do you assess the security posture of your third-party vendors?",
            "response_type": "yes_no", "required": True,
            "help_text": "Vendor risk management program with periodic assessments.",
            "mapped_controls": ["NIST SA-9", "SOC2 CC9.2", "ISO A.15.1.1"],
        },
        {
            "id": "SL-16", "category": "Compliance",
            "text": "What compliance certifications do you hold? (Select all that apply)",
            "response_type": "text", "required": True,
            "help_text": "SOC 2 Type II, ISO 27001, PCI DSS, HIPAA, FedRAMP, etc.",
            "mapped_controls": ["NIST CA-2", "SOC2 CC4.1"],
        },
        {
            "id": "SL-17", "category": "Compliance",
            "text": "Do you undergo regular third-party security audits?",
            "response_type": "yes_no", "required": True,
            "help_text": "Annual penetration testing and/or independent audits.",
            "mapped_controls": ["NIST CA-7", "SOC2 CC4.1"],
        },
        {
            "id": "SL-18", "category": "Personnel Security",
            "text": "Do you perform background checks on employees with access to customer data?",
            "response_type": "yes_no", "required": True,
            "help_text": "Pre-employment screening for roles handling sensitive data.",
            "mapped_controls": ["NIST PS-3", "SOC2 CC1.4", "ISO A.7.1.1"],
        },
        {
            "id": "SL-19", "category": "Personnel Security",
            "text": "Do you require security awareness training for all employees?",
            "response_type": "yes_no", "required": True,
            "help_text": "Annual security awareness training with phishing simulations.",
            "mapped_controls": ["NIST AT-2", "SOC2 CC1.4", "ISO A.7.2.2"],
        },
        {
            "id": "SL-20", "category": "Network Security",
            "text": "Do you segment your network and restrict access between zones?",
            "response_type": "yes_no", "required": True,
            "help_text": "Network segmentation between production, corporate, and DMZ.",
            "mapped_controls": ["NIST SC-7", "SOC2 CC6.6", "ISO A.13.1.3"],
        },
    ]

    DDQ_QUESTIONS = [
        {
            "id": "DDQ-01", "category": "General",
            "text": "Provide a brief description of your company and the services you provide.",
            "response_type": "text", "required": True,
            "help_text": "Company overview, services, and scope of engagement.",
            "mapped_controls": [],
        },
        {
            "id": "DDQ-02", "category": "General",
            "text": "How many employees does your organization have?",
            "response_type": "text", "required": True,
            "help_text": "Total headcount.",
            "mapped_controls": [],
        },
        {
            "id": "DDQ-03", "category": "Data Handling",
            "text": "What types of customer data will you process, store, or transmit?",
            "response_type": "text", "required": True,
            "help_text": "PII, PHI, financial data, credentials, etc.",
            "mapped_controls": ["NIST RA-2"],
        },
        {
            "id": "DDQ-04", "category": "Data Handling",
            "text": "Where will customer data be stored? Specify geographic locations.",
            "response_type": "text", "required": True,
            "help_text": "Data residency requirements.",
            "mapped_controls": ["NIST PE-18"],
        },
        {
            "id": "DDQ-05", "category": "Data Handling",
            "text": "Do you use sub-processors to handle customer data? If so, list them.",
            "response_type": "text", "required": True,
            "help_text": "Sub-processor disclosure for GDPR/privacy compliance.",
            "mapped_controls": ["NIST SA-9"],
        },
        {
            "id": "DDQ-06", "category": "Security Architecture",
            "text": "Describe your cloud infrastructure and hosting environment.",
            "response_type": "text", "required": True,
            "help_text": "AWS, Azure, GCP, on-premise, hybrid.",
            "mapped_controls": ["NIST SC-7"],
        },
        {
            "id": "DDQ-07", "category": "Security Architecture",
            "text": "Do you have a SOC 2 Type II report? If so, provide the audit period.",
            "response_type": "text", "required": True,
            "help_text": "Most recent SOC 2 Type II report details.",
            "mapped_controls": ["NIST CA-2", "SOC2 CC4.1"],
        },
        {
            "id": "DDQ-08", "category": "Security Architecture",
            "text": "Describe your logging and monitoring capabilities.",
            "response_type": "text", "required": True,
            "help_text": "SIEM, log retention, alerting, and monitoring coverage.",
            "mapped_controls": ["NIST AU-6", "SOC2 CC7.2"],
        },
        {
            "id": "DDQ-09", "category": "Privacy",
            "text": "Do you have a privacy policy? Provide a link.",
            "response_type": "text", "required": True,
            "help_text": "Public privacy policy URL.",
            "mapped_controls": [],
        },
        {
            "id": "DDQ-10", "category": "Privacy",
            "text": "Are you GDPR compliant? Do you support data subject access requests (DSARs)?",
            "response_type": "yes_no", "required": True,
            "help_text": "GDPR compliance and DSAR handling process.",
            "mapped_controls": [],
        },
    ]

    def create_template(
        self,
        session: Session,
        name: str,
        template_type: str,
        questions: list[dict],
        description: str = "",
        version: str = "1.0",
    ) -> QuestionnaireTemplate:
        """Create a new questionnaire template."""
        template = QuestionnaireTemplate(
            name=name,
            template_type=template_type,
            version=version,
            description=description,
            questions=questions,
            total_questions=len(questions),
            is_active=True,
        )
        session.add(template)
        session.flush()
        return template

    def seed_default_templates(self, session: Session) -> list[QuestionnaireTemplate]:
        """Create SIG Lite and basic DDQ templates if they don't exist."""
        templates = []

        # SIG Lite
        existing = (
            session.query(QuestionnaireTemplate)
            .filter(QuestionnaireTemplate.template_type == "sig_lite")
            .first()
        )
        if not existing:
            t = self.create_template(
                session,
                name="SIG Lite",
                template_type="sig_lite",
                questions=self.SIG_LITE_QUESTIONS,
                description="Standardized Information Gathering (SIG) Lite questionnaire - "
                "20 core security questions for vendor assessment.",
                version="1.0",
            )
            templates.append(t)

        # DDQ
        existing = (
            session.query(QuestionnaireTemplate)
            .filter(QuestionnaireTemplate.template_type == "ddq")
            .first()
        )
        if not existing:
            t = self.create_template(
                session,
                name="Security Due Diligence Questionnaire",
                template_type="ddq",
                questions=self.DDQ_QUESTIONS,
                description="Standard security due diligence questionnaire for vendor onboarding.",
                version="1.0",
            )
            templates.append(t)

        return templates

    def create_questionnaire(
        self,
        session: Session,
        template_id: str,
        vendor_name: str,
        vendor_email: str | None = None,
        due_days: int = 30,
        created_by: str = "",
    ) -> Questionnaire:
        """Create a new questionnaire for a vendor from a template."""
        template = (
            session.query(QuestionnaireTemplate)
            .filter(QuestionnaireTemplate.id == template_id)
            .first()
        )
        if not template:
            raise ValueError(f"Template not found: {template_id}")

        now = datetime.now(timezone.utc)
        q = Questionnaire(
            template_id=template_id,
            vendor_name=vendor_name,
            vendor_contact_email=vendor_email,
            status="draft",
            responses={},
            completion_pct=0.0,
            due_date=now + timedelta(days=due_days),
            created_by=created_by,
            created_at=now,
            updated_at=now,
        )
        session.add(q)
        session.flush()
        return q

    def submit_response(
        self,
        session: Session,
        questionnaire_id: str,
        question_id: str,
        answer: Any,
        notes: str = "",
    ) -> Questionnaire:
        """Submit a single response to a questionnaire question."""
        q = session.query(Questionnaire).filter(Questionnaire.id == questionnaire_id).first()
        if not q:
            raise ValueError(f"Questionnaire not found: {questionnaire_id}")

        responses = dict(q.responses or {})
        responses[question_id] = {
            "answer": answer,
            "notes": notes,
            "answered_at": datetime.now(timezone.utc).isoformat(),
        }
        q.responses = responses

        # Recalculate completion
        template = (
            session.query(QuestionnaireTemplate)
            .filter(QuestionnaireTemplate.id == q.template_id)
            .first()
        )
        if template and template.total_questions > 0:
            q.completion_pct = round(len(responses) / template.total_questions * 100, 1)

        q.updated_at = datetime.now(timezone.utc)
        session.flush()
        return q

    def submit_bulk_responses(
        self,
        session: Session,
        questionnaire_id: str,
        responses: dict,
    ) -> Questionnaire:
        """Submit multiple responses at once. responses = {question_id: {answer, notes}}."""
        q = session.query(Questionnaire).filter(Questionnaire.id == questionnaire_id).first()
        if not q:
            raise ValueError(f"Questionnaire not found: {questionnaire_id}")

        existing = dict(q.responses or {})
        now = datetime.now(timezone.utc).isoformat()

        for qid, resp in responses.items():
            if isinstance(resp, dict):
                existing[qid] = {
                    "answer": resp.get("answer"),
                    "notes": resp.get("notes", ""),
                    "answered_at": now,
                }
            else:
                existing[qid] = {"answer": resp, "notes": "", "answered_at": now}

        q.responses = existing

        template = (
            session.query(QuestionnaireTemplate)
            .filter(QuestionnaireTemplate.id == q.template_id)
            .first()
        )
        if template and template.total_questions > 0:
            q.completion_pct = round(len(existing) / template.total_questions * 100, 1)

        q.updated_at = datetime.now(timezone.utc)
        session.flush()
        return q

    def score_responses(self, session: Session, questionnaire_id: str) -> Questionnaire:
        """Score completed questionnaire: compute risk_score and risk_findings.

        Scoring logic:
        - yes_no questions: 'no' on security controls = high risk
        - Missing required responses = medium risk
        - Risk score is 0-100 (lower = better)
        """
        q = session.query(Questionnaire).filter(Questionnaire.id == questionnaire_id).first()
        if not q:
            raise ValueError(f"Questionnaire not found: {questionnaire_id}")

        template = (
            session.query(QuestionnaireTemplate)
            .filter(QuestionnaireTemplate.id == q.template_id)
            .first()
        )
        if not template:
            raise ValueError(f"Template not found: {q.template_id}")

        responses = q.responses or {}
        risk_findings: list[dict] = []
        total_weight = 0
        risk_weight = 0

        for question in template.questions:
            qid = question["id"]
            required = question.get("required", False)
            resp = responses.get(qid)
            weight = 5 if required else 3

            total_weight += weight

            if resp is None:
                if required:
                    risk_findings.append({
                        "question_id": qid,
                        "finding": f"Required question unanswered: {question['text'][:80]}",
                        "severity": "medium",
                    })
                    risk_weight += weight
            else:
                answer = resp.get("answer") if isinstance(resp, dict) else resp
                if question.get("response_type") == "yes_no":
                    # W-12: Check against per-question positive_answer (default "yes")
                    positive = question.get("positive_answer", "yes")
                    if str(answer).lower() not in (positive.lower(), "true", "t"):
                        severity = "high" if required else "medium"
                        risk_findings.append({
                            "question_id": qid,
                            "finding": f"Negative response: {question['text'][:80]}",
                            "severity": severity,
                        })
                        risk_weight += weight

        q.risk_score = round((risk_weight / total_weight * 100) if total_weight > 0 else 0, 1)
        q.risk_findings = risk_findings
        q.updated_at = datetime.now(timezone.utc)
        session.flush()
        return q

    def ai_suggest_answers(self, session: Session, questionnaire_id: str) -> Questionnaire:
        """Use existing compliance evidence to suggest answers.

        Queries ControlResult + Finding data to find evidence that answers each question.
        Populates ai_suggested_answers with {answer, confidence, source}.
        """
        q = session.query(Questionnaire).filter(Questionnaire.id == questionnaire_id).first()
        if not q:
            raise ValueError(f"Questionnaire not found: {questionnaire_id}")

        template = (
            session.query(QuestionnaireTemplate)
            .filter(QuestionnaireTemplate.id == q.template_id)
            .first()
        )
        if not template:
            raise ValueError(f"Template not found: {q.template_id}")

        suggestions: dict[str, dict] = {}

        # Build a lookup of compliant controls
        compliant_controls: set[str] = set()
        non_compliant_controls: set[str] = set()
        results = session.query(ControlResult).all()
        for r in results:
            key = f"{r.framework} {r.control_id}"
            if r.status == "compliant":
                compliant_controls.add(key)
            elif r.status == "non_compliant":
                non_compliant_controls.add(key)

        for question in template.questions:
            qid = question["id"]
            mapped = question.get("mapped_controls", [])

            if not mapped:
                continue

            # Check if we have evidence for the mapped controls
            matched_compliant = 0
            matched_non_compliant = 0
            source_controls: list[str] = []

            for control_ref in mapped:
                # Try matching against our control results
                for key in compliant_controls:
                    if control_ref.replace(" ", "") in key.replace(" ", "").replace("-", ""):
                        matched_compliant += 1
                        source_controls.append(key)
                        break
                for key in non_compliant_controls:
                    if control_ref.replace(" ", "") in key.replace(" ", "").replace("-", ""):
                        matched_non_compliant += 1
                        break

            if matched_compliant > 0 or matched_non_compliant > 0:
                matched_compliant + matched_non_compliant
                if question.get("response_type") == "yes_no":
                    answer = "Yes" if matched_compliant > matched_non_compliant else "No"
                else:
                    answer = (
                        f"Based on {matched_compliant} compliant control(s): "
                        f"{', '.join(source_controls[:3])}"
                    )

                confidence = round(matched_compliant / max(len(mapped), 1) * 100, 1)
                suggestions[qid] = {
                    "answer": answer,
                    "confidence": min(confidence, 100.0),
                    "source": f"Control results: {', '.join(source_controls[:5])}",
                }

        q.ai_suggested_answers = suggestions
        q.updated_at = datetime.now(timezone.utc)
        session.flush()
        return q

    def transition(
        self,
        session: Session,
        questionnaire_id: str,
        new_status: str,
        actor: str = "",
    ) -> Questionnaire:
        """Transition questionnaire status."""
        valid_statuses = {
            "draft", "sent", "in_progress", "completed",
            "reviewed", "accepted", "rejected",
        }
        valid_transitions = {
            "draft": {"sent", "in_progress"},
            "sent": {"in_progress", "draft"},
            "in_progress": {"completed", "draft"},
            "completed": {"reviewed", "in_progress"},
            "reviewed": {"accepted", "rejected", "completed"},
            "accepted": {"reviewed"},
            "rejected": {"reviewed", "in_progress"},
        }

        q = session.query(Questionnaire).filter(Questionnaire.id == questionnaire_id).first()
        if not q:
            raise ValueError(f"Questionnaire not found: {questionnaire_id}")

        if new_status not in valid_statuses:
            raise ValueError(f"Invalid status: {new_status}")

        allowed = valid_transitions.get(q.status, set())
        if new_status not in allowed:
            raise ValueError(
                f"Cannot transition from '{q.status}' to '{new_status}'. "
                f"Allowed: {allowed}"
            )

        now = datetime.now(timezone.utc)
        q.status = new_status

        if new_status == "sent":
            q.sent_at = now
        elif new_status == "completed":
            q.completed_at = now
        elif new_status in ("accepted", "rejected"):
            q.reviewed_by = actor
            q.reviewed_at = now

        q.updated_at = now
        session.flush()
        return q

    def overdue(self, session: Session) -> list[Questionnaire]:
        """Return questionnaires past due_date that aren't completed."""
        now = datetime.now(timezone.utc)
        rows = (
            session.query(Questionnaire)
            .filter(
                Questionnaire.due_date.isnot(None),
                Questionnaire.status.notin_(["completed", "reviewed", "accepted", "rejected"]),
            )
            .order_by(Questionnaire.due_date.asc())
            .all()
        )
        # W-4: ensure_aware before comparing due_date
        return [q for q in rows if ensure_aware(q.due_date) < now]

    def summary(self, session: Session) -> dict:
        """Return questionnaire stats."""
        total = session.query(func.count(Questionnaire.id)).scalar() or 0

        status_rows = (
            session.query(Questionnaire.status, func.count(Questionnaire.id))
            .group_by(Questionnaire.status)
            .all()
        )
        by_status = {s: c for s, c in status_rows}

        overdue_count = len(self.overdue(session))

        template_count = (
            session.query(func.count(QuestionnaireTemplate.id))
            .filter(QuestionnaireTemplate.is_active == True)  # noqa: E712
            .scalar() or 0
        )

        # Average risk score of scored questionnaires
        avg_risk = (
            session.query(func.avg(Questionnaire.risk_score))
            .filter(Questionnaire.risk_score != None)  # noqa: E711
            .scalar()
        )

        return {
            "total": total,
            "by_status": by_status,
            "overdue": overdue_count,
            "templates": template_count,
            "avg_risk_score": round(float(avg_risk), 1) if avg_risk else None,
        }

    # ------------------------------------------------------------------
    # #46: AI Auto-Response — keyword-matched evidence from pipeline data
    # ------------------------------------------------------------------

    def _build_evidence_corpus(self, session: Session) -> dict[str, Any]:
        """Build a reusable evidence corpus from ControlResult + Finding tables.

        Returns:
            {
              "results": list[ControlResult],
              "findings": list[Finding],
              "compliant_controls": set[str],   # "framework control_id"
              "non_compliant_controls": set[str],
              "finding_index": {word: [Finding, ...]},
              "result_index": {word: [ControlResult, ...]},
            }
        """
        results: list[ControlResult] = session.query(ControlResult).all()
        findings: list[Finding] = session.query(Finding).all()

        compliant: set[str] = set()
        non_compliant: set[str] = set()
        result_index: dict[str, list[ControlResult]] = {}

        for r in results:
            key = f"{r.framework} {r.control_id}"
            if r.status == "compliant":
                compliant.add(key)
            elif r.status == "non_compliant":
                non_compliant.add(key)

            # Index by words from assertion_name
            for word in self._tokenize(r.assertion_name or ""):
                result_index.setdefault(word, []).append(r)

        finding_index: dict[str, list[Finding]] = {}
        for f in findings:
            for word in self._tokenize(f.title or ""):
                finding_index.setdefault(word, []).append(f)

        return {
            "results": results,
            "findings": findings,
            "compliant_controls": compliant,
            "non_compliant_controls": non_compliant,
            "result_index": result_index,
            "finding_index": finding_index,
        }

    @staticmethod
    def _tokenize(text: str) -> list[str]:
        """Extract lowercase words of 3+ characters from text."""
        return [w.lower() for w in re.findall(r"[a-zA-Z]{3,}", text)]

    @staticmethod
    def _score_question_against_corpus(
        question_text: str,
        mapped_controls: list[str],
        corpus: dict[str, Any],
    ) -> dict[str, Any]:
        """Return a relevance-scored evidence bundle for a single question.

        Matching strategy (in priority order):
        1. Exact control ID match against mapped_controls
        2. Keyword overlap between question text and assertion_name / finding title
        """
        compliant = corpus["compliant_controls"]
        non_compliant = corpus["non_compliant_controls"]
        result_index = corpus["result_index"]
        finding_index = corpus["finding_index"]

        matched_compliant: list[str] = []
        matched_non_compliant: list[str] = []
        evidence_snippets: list[str] = []
        remediation_snippets: list[str] = []

        # --- Strategy 1: mapped control IDs ---
        for control_ref in mapped_controls:
            norm = control_ref.replace(" ", "").replace("-", "").lower()
            for key in compliant:
                if norm in key.replace(" ", "").replace("-", "").lower():
                    matched_compliant.append(key)
                    break
            for key in non_compliant:
                if norm in key.replace(" ", "").replace("-", "").lower():
                    matched_non_compliant.append(key)
                    break

        # --- Strategy 2: keyword matching ---
        question_words = QuestionnaireManager._tokenize(question_text)
        seen_result_ids: set[str] = set()
        seen_finding_ids: set[str] = set()

        for word in question_words:
            for r in result_index.get(word, []):
                if r.id not in seen_result_ids:
                    seen_result_ids.add(r.id)
                    key = f"{r.framework} {r.control_id}"
                    if r.assertion_passed is True:
                        matched_compliant.append(key)
                        if r.assertion_name:
                            evidence_snippets.append(r.assertion_name)
                    elif r.assertion_passed is False:
                        matched_non_compliant.append(key)
                        if r.remediation_summary:
                            remediation_snippets.append(r.remediation_summary[:120])
            for f in finding_index.get(word, []):
                if f.id not in seen_finding_ids:
                    seen_finding_ids.add(f.id)
                    evidence_snippets.append(f.title[:100])

        return {
            "matched_compliant": matched_compliant,
            "matched_non_compliant": matched_non_compliant,
            "evidence_snippets": evidence_snippets[:5],
            "remediation_snippets": remediation_snippets[:3],
        }

    def auto_respond(self, session: Session, questionnaire_id: str) -> Questionnaire:
        """Bulk-populate ai_suggested_answers from control results + finding evidence.

        For each question in the questionnaire template:
        - Searches ControlResult.assertion_name and Finding.title for keyword matches
          against the question text, plus mapped_controls control ID matching.
        - For yes/no questions: "Yes, [evidence]" if passing assertion found,
          else "No, [gap with remediation plan]".
        - For text questions: composes answer from relevant finding summaries.

        Persists results to questionnaire.ai_suggested_answers.
        """
        q = session.query(Questionnaire).filter(Questionnaire.id == questionnaire_id).first()
        if not q:
            raise ValueError(f"Questionnaire not found: {questionnaire_id}")

        template = (
            session.query(QuestionnaireTemplate)
            .filter(QuestionnaireTemplate.id == q.template_id)
            .first()
        )
        if not template:
            raise ValueError(f"Template not found: {q.template_id}")

        corpus = self._build_evidence_corpus(session)
        suggestions: dict[str, dict] = {}

        for question in template.questions:
            qid = question["id"]
            question_text = question.get("text", "")
            mapped_controls = question.get("mapped_controls", [])
            response_type = question.get("response_type", "text")

            evidence = self._score_question_against_corpus(
                question_text, mapped_controls, corpus
            )

            n_compliant = len(evidence["matched_compliant"])
            n_non_compliant = len(evidence["matched_non_compliant"])

            if n_compliant == 0 and n_non_compliant == 0:
                # No matching evidence — skip
                continue

            if response_type == "yes_no":
                if n_compliant >= n_non_compliant:
                    snippets = "; ".join(evidence["evidence_snippets"][:3]) or "pipeline evidence"
                    answer = f"Yes, {snippets}."
                    confidence = round(n_compliant / max(n_compliant + n_non_compliant, 1) * 100, 1)
                else:
                    remediations = "; ".join(evidence["remediation_snippets"][:2]) or "see remediation plan"
                    answer = f"No, {remediations}."
                    confidence = round(n_non_compliant / max(n_compliant + n_non_compliant, 1) * 100, 1)
            else:
                # Text question — compose from finding summaries
                parts: list[str] = []
                if evidence["evidence_snippets"]:
                    parts.append("Evidence: " + "; ".join(evidence["evidence_snippets"][:3]) + ".")
                if evidence["matched_compliant"]:
                    parts.append(
                        f"Compliant controls: {', '.join(evidence['matched_compliant'][:3])}."
                    )
                if evidence["matched_non_compliant"]:
                    parts.append(
                        f"Non-compliant controls: {', '.join(evidence['matched_non_compliant'][:3])}."
                    )
                answer = " ".join(parts) if parts else "No automated evidence available."
                confidence = round(
                    n_compliant / max(n_compliant + n_non_compliant, 1) * 100, 1
                )

            source_controls = (evidence["matched_compliant"] + evidence["matched_non_compliant"])[:5]
            suggestions[qid] = {
                "answer": answer,
                "confidence": min(confidence, 100.0),
                "source": f"Control results: {', '.join(source_controls)}" if source_controls else "Keyword match",
            }

        q.ai_suggested_answers = suggestions
        q.updated_at = datetime.now(timezone.utc)
        session.flush()
        return q

    def suggest_response(self, session: Session, question_text: str) -> dict[str, Any]:
        """On-demand suggestion for a free-text question.

        Given a raw question string, searches ControlResult and Finding
        evidence and returns a suggested answer with confidence and sources.

        Returns a dict (not persisted to DB):
            {
              "question": str,
              "suggested_answer": str,
              "confidence": float,      # 0-100
              "sources": list[str],     # control keys used as evidence
              "evidence_snippets": list[str],
            }
        """
        if not question_text or not question_text.strip():
            return {
                "question": question_text,
                "suggested_answer": "No question text provided.",
                "confidence": 0.0,
                "sources": [],
                "evidence_snippets": [],
            }

        corpus = self._build_evidence_corpus(session)
        evidence = self._score_question_against_corpus(
            question_text,
            mapped_controls=[],  # no pre-mapped controls for ad-hoc questions
            corpus=corpus,
        )

        n_compliant = len(evidence["matched_compliant"])
        n_non_compliant = len(evidence["matched_non_compliant"])
        total = n_compliant + n_non_compliant

        # Detect yes/no phrasing heuristically
        yes_no_patterns = re.compile(
            r"\b(do you|does your|have you|is there|are there|can you|will you)\b",
            re.IGNORECASE,
        )
        is_yes_no = bool(yes_no_patterns.search(question_text))

        if total == 0:
            return {
                "question": question_text,
                "suggested_answer": "No automated evidence found in the compliance pipeline.",
                "confidence": 0.0,
                "sources": [],
                "evidence_snippets": [],
            }

        if is_yes_no:
            if n_compliant >= n_non_compliant:
                snippets = "; ".join(evidence["evidence_snippets"][:3]) or "pipeline evidence"
                answer = f"Yes, {snippets}."
            else:
                remediations = "; ".join(evidence["remediation_snippets"][:2]) or "see remediation plan"
                answer = f"No, {remediations}."
        else:
            parts: list[str] = []
            if evidence["evidence_snippets"]:
                parts.append("Evidence: " + "; ".join(evidence["evidence_snippets"][:3]) + ".")
            if evidence["matched_compliant"]:
                parts.append(f"Compliant controls: {', '.join(evidence['matched_compliant'][:3])}.")
            if evidence["matched_non_compliant"]:
                parts.append(f"Non-compliant controls: {', '.join(evidence['matched_non_compliant'][:3])}.")
            answer = " ".join(parts) if parts else "No automated evidence available."

        confidence = round(n_compliant / max(total, 1) * 100, 1)
        sources = (evidence["matched_compliant"] + evidence["matched_non_compliant"])[:5]

        return {
            "question": question_text,
            "suggested_answer": answer,
            "confidence": min(confidence, 100.0),
            "sources": sources,
            "evidence_snippets": evidence["evidence_snippets"],
        }

    # ------------------------------------------------------------------
    # Phase 2: AI-powered auto-response
    # ------------------------------------------------------------------

    def _keyword_respond(
        self,
        question: dict[str, Any],
        corpus: dict[str, Any],
    ) -> dict[str, Any]:
        """Generate a keyword-matched response for a single question.

        This is the deterministic fallback used by ``ai_respond()`` when
        AI is unavailable.  Reuses the same evidence-matching logic as
        ``auto_respond()`` but operates on a single question and returns
        a response dict rather than persisting to the DB.

        Args:
            question: A question dict from the template (must have ``id``,
                ``text``, ``mapped_controls``, ``response_type``).
            corpus: Evidence corpus from ``_build_evidence_corpus()``.

        Returns:
            Dict with ``answer``, ``confidence``, ``source``, and
            ``ai_generated`` (always ``False``).
        """
        question_text = question.get("text", "")
        mapped_controls = question.get("mapped_controls", [])
        response_type = question.get("response_type", "text")

        evidence = self._score_question_against_corpus(
            question_text, mapped_controls, corpus,
        )

        n_compliant = len(evidence["matched_compliant"])
        n_non_compliant = len(evidence["matched_non_compliant"])

        if n_compliant == 0 and n_non_compliant == 0:
            return {
                "answer": "No automated evidence available.",
                "confidence": 0.0,
                "source": "none",
                "ai_generated": False,
            }

        if response_type == "yes_no":
            if n_compliant >= n_non_compliant:
                snippets = "; ".join(evidence["evidence_snippets"][:3]) or "pipeline evidence"
                answer = f"Yes, {snippets}."
                confidence = round(
                    n_compliant / max(n_compliant + n_non_compliant, 1) * 100, 1,
                )
            else:
                remediations = (
                    "; ".join(evidence["remediation_snippets"][:2]) or "see remediation plan"
                )
                answer = f"No, {remediations}."
                confidence = round(
                    n_non_compliant / max(n_compliant + n_non_compliant, 1) * 100, 1,
                )
        else:
            parts: list[str] = []
            if evidence["evidence_snippets"]:
                parts.append("Evidence: " + "; ".join(evidence["evidence_snippets"][:3]) + ".")
            if evidence["matched_compliant"]:
                parts.append(
                    f"Compliant controls: {', '.join(evidence['matched_compliant'][:3])}.",
                )
            if evidence["matched_non_compliant"]:
                parts.append(
                    f"Non-compliant controls: {', '.join(evidence['matched_non_compliant'][:3])}.",
                )
            answer = " ".join(parts) if parts else "No automated evidence available."
            confidence = round(
                n_compliant / max(n_compliant + n_non_compliant, 1) * 100, 1,
            )

        source_controls = (
            evidence["matched_compliant"] + evidence["matched_non_compliant"]
        )[:5]

        return {
            "answer": answer,
            "confidence": min(confidence, 100.0),
            "source": (
                f"Control results: {', '.join(source_controls)}"
                if source_controls
                else "Keyword match"
            ),
            "ai_generated": False,
        }

    def ai_respond(
        self,
        session: Session,
        questionnaire_id: str,
    ) -> Questionnaire:
        """AI-powered auto-response for questionnaire questions.

        For each question in the questionnaire template, calls
        ``AIService.reason(AITask.QUESTIONNAIRE_RESPONSE, ...)`` with the
        question text, mapped controls, and evidence corpus.  The AI
        composes professional responses with confidence scores.

        When AI is off or fails for a given question, falls back to
        ``_keyword_respond()`` which uses the same deterministic
        keyword-matching logic as ``auto_respond()``.

        This method does NOT modify ``auto_respond()`` -- it is a
        separate AI-enhanced path that consumers opt into explicitly.

        Args:
            session: SQLAlchemy database session.
            questionnaire_id: ID of the questionnaire to populate.

        Returns:
            The updated Questionnaire with ``ai_suggested_answers``
            populated.  Each answer dict includes an ``ai_generated``
            boolean so the caller knows the provenance.

        Raises:
            ValueError: If questionnaire or template not found.
        """
        from warlock.ai import get_ai_service, AITask

        q = (
            session.query(Questionnaire)
            .filter(Questionnaire.id == questionnaire_id)
            .first()
        )
        if not q:
            raise ValueError(f"Questionnaire not found: {questionnaire_id}")

        template = (
            session.query(QuestionnaireTemplate)
            .filter(QuestionnaireTemplate.id == q.template_id)
            .first()
        )
        if not template:
            raise ValueError(f"Template not found: {q.template_id}")

        corpus = self._build_evidence_corpus(session)
        ai = get_ai_service()
        suggestions: dict[str, dict[str, Any]] = {}

        for question in template.questions:
            qid = question["id"]
            question_text = question.get("text", "")
            mapped_controls = question.get("mapped_controls", [])

            # Build evidence context for this question
            evidence = self._score_question_against_corpus(
                question_text, mapped_controls, corpus,
            )

            context = {
                "question": question_text,
                "question_id": qid,
                "response_type": question.get("response_type", "text"),
                "mapped_controls": mapped_controls,
                "evidence": {
                    "compliant_controls": evidence["matched_compliant"][:10],
                    "non_compliant_controls": evidence["matched_non_compliant"][:10],
                    "evidence_snippets": evidence["evidence_snippets"][:5],
                    "remediation_snippets": evidence["remediation_snippets"][:3],
                },
            }

            result = ai.reason(
                task=AITask.QUESTIONNAIRE_RESPONSE,
                context=context,
                fallback=lambda q=question, c=corpus: self._keyword_respond(q, c),
            )

            value = result.value
            if result.ai_used and isinstance(value, dict):
                suggestions[qid] = {
                    "answer": value.get("response", str(value)),
                    "confidence": result.confidence * 100.0,
                    "source": f"AI ({result.provider}/{result.model})",
                    "ai_generated": True,
                }
            elif isinstance(value, dict) and "answer" in value:
                # Fallback dict from _keyword_respond
                suggestions[qid] = value
            else:
                suggestions[qid] = {
                    "answer": str(value) if value else "No response generated.",
                    "confidence": 0.0,
                    "source": "fallback",
                    "ai_generated": False,
                }

        q.ai_suggested_answers = suggestions
        q.updated_at = datetime.now(timezone.utc)
        session.flush()

        log.info(
            "ai_respond for questionnaire %s: %d/%d questions answered, "
            "%d AI-generated",
            questionnaire_id,
            len(suggestions),
            len(template.questions),
            sum(1 for s in suggestions.values() if s.get("ai_generated")),
        )

        return q
