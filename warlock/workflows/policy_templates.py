"""Policy Template Library and Acknowledgment Tracking.

Ships 20+ built-in policy templates with title, category, content outline,
and applicable framework mappings. Provides acknowledgment tracking for
policy assignments.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import uuid4

log = logging.getLogger(__name__)


@dataclass
class PolicyTemplate:
    """A built-in policy template."""

    slug: str
    title: str
    category: str
    frameworks: list[str]
    outline: list[str]
    description: str = ""


@dataclass
class PolicyAcknowledgment:
    """Record of a user acknowledging a policy."""

    id: str
    policy_id: str
    policy_name: str
    user_email: str
    acknowledged_at: datetime
    version: int = 1
    notes: str = ""


# ---------------------------------------------------------------------------
# Built-in policy templates (20+)
# ---------------------------------------------------------------------------

TEMPLATES: list[PolicyTemplate] = [
    PolicyTemplate(
        slug="acceptable-use",
        title="Acceptable Use Policy",
        category="General",
        frameworks=["soc2", "iso27001", "nist-800-53", "hipaa"],
        description="Defines acceptable use of organizational IT resources.",
        outline=[
            "1. Purpose and scope",
            "2. Authorized use of systems and data",
            "3. Prohibited activities",
            "4. Personal use guidelines",
            "5. Monitoring and enforcement",
            "6. Consequences of violation",
            "7. Acknowledgment requirement",
        ],
    ),
    PolicyTemplate(
        slug="data-classification",
        title="Data Classification Policy",
        category="Data Protection",
        frameworks=["soc2", "iso27001", "nist-800-53", "gdpr", "hipaa", "pci-dss"],
        description="Establishes data classification levels and handling requirements.",
        outline=[
            "1. Classification levels (Public, Internal, Confidential, Restricted)",
            "2. Classification criteria and examples",
            "3. Labeling and marking requirements",
            "4. Handling procedures per classification level",
            "5. Storage and transmission requirements",
            "6. Declassification and reclassification",
            "7. Roles and responsibilities (data owners, custodians)",
        ],
    ),
    PolicyTemplate(
        slug="incident-response",
        title="Incident Response Policy",
        category="Security Operations",
        frameworks=["soc2", "iso27001", "nist-800-53", "nist-csf", "hipaa", "pci-dss", "cmmc"],
        description="Defines procedures for detecting, responding to, and recovering from security incidents.",
        outline=[
            "1. Incident definition and severity classification",
            "2. Incident response team roles and contact info",
            "3. Detection and reporting procedures",
            "4. Triage and initial response",
            "5. Containment, eradication, and recovery",
            "6. Evidence preservation and chain of custody",
            "7. Communication and notification (internal, external, regulatory)",
            "8. Post-incident review and lessons learned",
            "9. Regulatory notification timelines (72h GDPR, state breach laws)",
        ],
    ),
    PolicyTemplate(
        slug="password",
        title="Password Policy",
        category="Access Control",
        frameworks=["soc2", "iso27001", "nist-800-53", "hipaa", "pci-dss", "cmmc"],
        description="Sets password complexity, rotation, and management requirements.",
        outline=[
            "1. Minimum length and complexity requirements",
            "2. Password rotation cadence",
            "3. Password history (reuse prevention)",
            "4. Multi-factor authentication requirements",
            "5. Password storage and transmission (hashing, TLS)",
            "6. Service account and privileged account passwords",
            "7. Password manager requirements",
        ],
    ),
    PolicyTemplate(
        slug="remote-access",
        title="Remote Access Policy",
        category="Access Control",
        frameworks=["soc2", "iso27001", "nist-800-53", "cmmc"],
        description="Controls remote access to organizational systems and data.",
        outline=[
            "1. Authorized remote access methods (VPN, ZTNA)",
            "2. Authentication requirements for remote access",
            "3. Device requirements (managed devices, MDM enrollment)",
            "4. Network security requirements (encryption, split tunneling)",
            "5. Session timeout and idle disconnect",
            "6. Logging and monitoring of remote sessions",
            "7. Incident response for compromised remote access",
        ],
    ),
    PolicyTemplate(
        slug="byod",
        title="Bring Your Own Device (BYOD) Policy",
        category="Endpoint Security",
        frameworks=["soc2", "iso27001", "nist-800-53"],
        description="Governs use of personal devices for work purposes.",
        outline=[
            "1. Scope — which personal devices are permitted",
            "2. Registration and MDM enrollment requirements",
            "3. Security requirements (encryption, screen lock, OS patching)",
            "4. Acceptable use on personal devices",
            "5. Data separation (containers, work profiles)",
            "6. Remote wipe and lost device procedures",
            "7. Employee offboarding — data removal",
        ],
    ),
    PolicyTemplate(
        slug="data-retention",
        title="Data Retention Policy",
        category="Data Protection",
        frameworks=["soc2", "iso27001", "gdpr", "hipaa", "pci-dss"],
        description="Defines retention periods and destruction procedures for data.",
        outline=[
            "1. Retention schedule by data category",
            "2. Legal and regulatory retention requirements",
            "3. Legal hold procedures",
            "4. Destruction methods (secure deletion, media sanitization)",
            "5. Backup and archive retention",
            "6. Exceptions and override process",
            "7. Annual review and update cadence",
        ],
    ),
    PolicyTemplate(
        slug="encryption",
        title="Encryption Policy",
        category="Data Protection",
        frameworks=["soc2", "iso27001", "nist-800-53", "hipaa", "pci-dss", "cmmc", "fedramp"],
        description="Mandates encryption standards for data at rest and in transit.",
        outline=[
            "1. Encryption requirements by data classification",
            "2. Approved algorithms and key lengths (AES-256, RSA-2048+)",
            "3. Encryption at rest (disk, database, backup)",
            "4. Encryption in transit (TLS 1.2+, mTLS)",
            "5. Key management lifecycle (generation, rotation, revocation)",
            "6. Hardware security modules (HSM) requirements",
            "7. Certificate management",
        ],
    ),
    PolicyTemplate(
        slug="access-control",
        title="Access Control Policy",
        category="Access Control",
        frameworks=["soc2", "iso27001", "nist-800-53", "hipaa", "pci-dss", "cmmc", "fedramp"],
        description="Defines access control principles and procedures.",
        outline=[
            "1. Least privilege principle",
            "2. Role-based access control (RBAC) framework",
            "3. Access provisioning and deprovisioning procedures",
            "4. Access review cadence (quarterly, annual)",
            "5. Privileged access management (PAM)",
            "6. Segregation of duties (SoD)",
            "7. Emergency and break-glass access procedures",
            "8. Third-party and contractor access",
        ],
    ),
    PolicyTemplate(
        slug="change-management",
        title="Change Management Policy",
        category="Operations",
        frameworks=["soc2", "iso27001", "nist-800-53", "pci-dss", "cmmc"],
        description="Controls changes to production systems and infrastructure.",
        outline=[
            "1. Change request and approval workflow",
            "2. Change classification (standard, normal, emergency)",
            "3. Change Advisory Board (CAB) process",
            "4. Testing and validation requirements",
            "5. Rollback procedures",
            "6. Post-implementation review",
            "7. Emergency change procedures",
        ],
    ),
    PolicyTemplate(
        slug="bcp",
        title="Business Continuity Policy",
        category="Resilience",
        frameworks=["soc2", "iso27001", "nist-800-53", "hipaa", "fedramp"],
        description="Ensures business continuity and disaster recovery capabilities.",
        outline=[
            "1. Business impact analysis (BIA) requirements",
            "2. Recovery time objectives (RTO) and recovery point objectives (RPO)",
            "3. Disaster recovery procedures",
            "4. Backup strategy and testing",
            "5. Crisis communication plan",
            "6. Testing cadence (annual tabletop, semi-annual DR test)",
            "7. Third-party dependency management",
        ],
    ),
    PolicyTemplate(
        slug="vendor-management",
        title="Vendor Management Policy",
        category="Third Party",
        frameworks=["soc2", "iso27001", "nist-800-53", "hipaa", "pci-dss"],
        description="Governs third-party vendor risk assessment and monitoring.",
        outline=[
            "1. Vendor risk tiering (critical, high, medium, low)",
            "2. Due diligence requirements per tier",
            "3. Security assessment questionnaires (SIG, CAIQ)",
            "4. SOC 2 / ISO 27001 report review",
            "5. Contract security requirements",
            "6. Ongoing monitoring and reassessment cadence",
            "7. Vendor offboarding and data return/destruction",
        ],
    ),
    PolicyTemplate(
        slug="privacy",
        title="Privacy Policy",
        category="Privacy",
        frameworks=["gdpr", "hipaa", "iso27701"],
        description="Defines privacy principles and data subject rights.",
        outline=[
            "1. Lawful basis for processing",
            "2. Data subject rights (access, rectification, erasure, portability)",
            "3. Consent management",
            "4. Data protection impact assessments (DPIA)",
            "5. Cross-border data transfers",
            "6. Data breach notification procedures",
            "7. Data Protection Officer (DPO) role",
            "8. Privacy by design and default",
        ],
    ),
    PolicyTemplate(
        slug="code-of-conduct",
        title="Code of Conduct",
        category="General",
        frameworks=["soc2", "iso27001"],
        description="Establishes ethical standards and expected behavior.",
        outline=[
            "1. Ethical principles and values",
            "2. Conflicts of interest",
            "3. Confidentiality obligations",
            "4. Reporting concerns and violations",
            "5. Non-retaliation protections",
            "6. Consequences of violations",
            "7. Annual acknowledgment requirement",
        ],
    ),
    PolicyTemplate(
        slug="clean-desk",
        title="Clean Desk Policy",
        category="Physical Security",
        frameworks=["soc2", "iso27001", "hipaa", "pci-dss"],
        description="Prevents unauthorized access to sensitive information in physical workspaces.",
        outline=[
            "1. Clear desk requirements at end of day",
            "2. Secure storage for sensitive documents",
            "3. Screen lock requirements when away",
            "4. Printer and copier security (secure print)",
            "5. Visitor management and escort requirements",
            "6. Shredding and secure disposal",
        ],
    ),
    PolicyTemplate(
        slug="mobile-device",
        title="Mobile Device Management Policy",
        category="Endpoint Security",
        frameworks=["soc2", "iso27001", "nist-800-53", "hipaa", "cmmc"],
        description="Secures mobile devices accessing organizational data.",
        outline=[
            "1. Approved mobile operating systems and versions",
            "2. MDM enrollment requirements",
            "3. Device encryption and screen lock",
            "4. Application whitelisting and blacklisting",
            "5. Remote wipe capabilities",
            "6. Lost or stolen device reporting",
            "7. Jailbroken/rooted device prohibition",
        ],
    ),
    PolicyTemplate(
        slug="social-media",
        title="Social Media Policy",
        category="General",
        frameworks=["soc2", "iso27001"],
        description="Governs employee use of social media regarding company information.",
        outline=[
            "1. Authorized social media representatives",
            "2. Prohibited disclosures (confidential info, customer data)",
            "3. Personal use guidelines",
            "4. Brand representation standards",
            "5. Incident response for social media breaches",
        ],
    ),
    PolicyTemplate(
        slug="whistleblower",
        title="Whistleblower Policy",
        category="General",
        frameworks=["soc2", "iso27001"],
        description="Protects employees who report compliance violations.",
        outline=[
            "1. Reporting channels (anonymous hotline, email, manager)",
            "2. Scope of reportable concerns",
            "3. Investigation process",
            "4. Non-retaliation protections",
            "5. Confidentiality of reports",
            "6. Regulatory reporting obligations",
        ],
    ),
    PolicyTemplate(
        slug="third-party-risk",
        title="Third-Party Risk Management Policy",
        category="Third Party",
        frameworks=["soc2", "iso27001", "nist-800-53", "cmmc"],
        description="Extends risk management to third-party relationships.",
        outline=[
            "1. Third-party inventory and classification",
            "2. Risk assessment methodology",
            "3. Security requirements in contracts",
            "4. Right-to-audit clauses",
            "5. Continuous monitoring requirements",
            "6. Subprocessor management",
            "7. Termination and transition planning",
        ],
    ),
    PolicyTemplate(
        slug="information-security",
        title="Information Security Policy",
        category="Security",
        frameworks=["soc2", "iso27001", "nist-800-53", "hipaa", "pci-dss", "cmmc", "fedramp"],
        description="Top-level policy establishing the organization's information security program.",
        outline=[
            "1. Policy statement and objectives",
            "2. Scope and applicability",
            "3. Roles and responsibilities (CISO, security team, all employees)",
            "4. Risk management approach",
            "5. Security governance structure",
            "6. Compliance requirements",
            "7. Policy review and update cadence (annual)",
            "8. Exception process",
            "9. Enforcement and disciplinary actions",
        ],
    ),
    PolicyTemplate(
        slug="vulnerability-management",
        title="Vulnerability Management Policy",
        category="Security Operations",
        frameworks=["soc2", "iso27001", "nist-800-53", "pci-dss", "cmmc", "fedramp"],
        description="Defines vulnerability scanning, assessment, and remediation procedures.",
        outline=[
            "1. Scanning frequency and coverage",
            "2. Vulnerability severity classification (CVSS, EPSS)",
            "3. Remediation SLAs by severity",
            "4. Patch management procedures",
            "5. Exception and risk acceptance process",
            "6. Penetration testing cadence",
            "7. Reporting and metrics",
        ],
    ),
    PolicyTemplate(
        slug="logging-monitoring",
        title="Logging and Monitoring Policy",
        category="Security Operations",
        frameworks=["soc2", "iso27001", "nist-800-53", "hipaa", "pci-dss", "cmmc", "fedramp"],
        description="Defines logging, monitoring, and alerting requirements.",
        outline=[
            "1. Log sources and types required",
            "2. Log retention periods",
            "3. Log integrity and tamper protection",
            "4. Monitoring and alerting thresholds",
            "5. Log review cadence",
            "6. SIEM/SOAR integration requirements",
            "7. Incident escalation from monitoring alerts",
        ],
    ),
]

# Index by slug for fast lookup
_TEMPLATE_INDEX: dict[str, PolicyTemplate] = {t.slug: t for t in TEMPLATES}


class PolicyTemplateLibrary:
    """Manages policy templates and acknowledgment tracking."""

    def __init__(self, session=None) -> None:
        self._session = session

    @staticmethod
    def list_templates(
        category: str | None = None,
        framework: str | None = None,
    ) -> list[PolicyTemplate]:
        """List available policy templates with optional filters."""
        results = TEMPLATES
        if category:
            cat_lower = category.lower()
            results = [t for t in results if t.category.lower() == cat_lower]
        if framework:
            fw_lower = framework.lower()
            results = [t for t in results if any(fw_lower in f.lower() for f in t.frameworks)]
        return results

    @staticmethod
    def get_template(slug: str) -> PolicyTemplate | None:
        """Get a template by slug."""
        return _TEMPLATE_INDEX.get(slug)

    @staticmethod
    def categories() -> list[str]:
        """List all unique template categories."""
        return sorted(set(t.category for t in TEMPLATES))

    def acknowledge(
        self,
        policy_name: str,
        user_email: str,
        notes: str = "",
    ) -> PolicyAcknowledgment:
        """Record a user's acknowledgment of a policy.

        Stores in saved_queries with query_type='policy_ack'.
        """
        from warlock.db.models import SavedQuery

        if self._session is None:
            raise RuntimeError("Session required for acknowledgment tracking")

        ack_id = str(uuid4())
        now = datetime.now(timezone.utc)

        record = SavedQuery(
            id=ack_id,
            name=f"ack:{policy_name}:{user_email}",
            description=notes or f"Policy acknowledgment by {user_email}",
            sql_text="",
            query_type="policy_ack",
            parameters={
                "policy_name": policy_name,
                "user_email": user_email,
                "acknowledged_at": now.isoformat(),
                "notes": notes,
            },
            shared=False,
            created_by=user_email,
        )
        self._session.add(record)
        self._session.flush()

        return PolicyAcknowledgment(
            id=ack_id,
            policy_id=policy_name,
            policy_name=policy_name,
            user_email=user_email,
            acknowledged_at=now,
            notes=notes,
        )

    def list_acknowledgments(
        self,
        policy_name: str | None = None,
        user_email: str | None = None,
    ) -> list[PolicyAcknowledgment]:
        """List policy acknowledgments with optional filters."""
        from warlock.db.models import SavedQuery
        from warlock.utils import ensure_aware

        if self._session is None:
            raise RuntimeError("Session required for acknowledgment tracking")

        q = self._session.query(SavedQuery).filter(
            SavedQuery.query_type == "policy_ack",
        )
        results = q.order_by(SavedQuery.created_at.desc()).all()

        acks: list[PolicyAcknowledgment] = []
        for r in results:
            params = r.parameters or {}
            p_name = params.get("policy_name", "")
            p_email = params.get("user_email", "")

            if policy_name and p_name != policy_name:
                continue
            if user_email and p_email != user_email:
                continue

            acked_at = r.created_at
            try:
                if params.get("acknowledged_at"):
                    acked_at = datetime.fromisoformat(params["acknowledged_at"])
            except (ValueError, TypeError):
                pass

            acks.append(
                PolicyAcknowledgment(
                    id=r.id,
                    policy_id=p_name,
                    policy_name=p_name,
                    user_email=p_email,
                    acknowledged_at=ensure_aware(acked_at)
                    if acked_at
                    else datetime.now(timezone.utc),
                    notes=params.get("notes", ""),
                )
            )
        return acks
