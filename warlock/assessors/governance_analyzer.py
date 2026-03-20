"""Governance control content analysis (#60).

Goes beyond "does the policy document exist?" to evaluate whether
governance documents are current, reviewed/approved, and cover the
required policy areas for a given compliance framework.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from warlock.db.models import Finding

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# NIST 800-53 "-1" controls -> required policy document types
# ---------------------------------------------------------------------------

NIST_POLICY_MAP: dict[str, list[str]] = {
    "AC-1": ["access control policy", "access control procedures"],
    "AT-1": ["security awareness training policy", "training procedures"],
    "AU-1": ["audit and accountability policy", "audit procedures"],
    "CA-1": ["assessment and authorization policy", "assessment procedures"],
    "CM-1": ["configuration management policy", "configuration management procedures"],
    "CP-1": ["contingency planning policy", "contingency planning procedures"],
    "IA-1": ["identification and authentication policy", "authentication procedures"],
    "IR-1": ["incident response policy", "incident response procedures"],
    "MA-1": ["maintenance policy", "maintenance procedures"],
    "MP-1": ["media protection policy", "media protection procedures"],
    "PE-1": ["physical and environmental protection policy", "physical security procedures"],
    "PL-1": ["planning policy", "security planning procedures"],
    "PM-1": ["program management policy", "information security program plan"],
    "PS-1": ["personnel security policy", "personnel security procedures"],
    "RA-1": ["risk assessment policy", "risk assessment procedures"],
    "SA-1": ["system and services acquisition policy", "acquisition procedures"],
    "SC-1": ["system and communications protection policy", "communications security procedures"],
    "SI-1": ["system and information integrity policy", "integrity procedures"],
    "SR-1": ["supply chain risk management policy", "supply chain procedures"],
}

# Keyword variants to match page titles against required policy types.
# Each entry maps a canonical policy area to a set of keywords that would
# indicate a Confluence page covers that area.
_POLICY_KEYWORDS: dict[str, list[str]] = {
    "access control": ["access control", "access management", "logical access"],
    "security awareness training": ["security awareness", "training", "security training"],
    "audit and accountability": ["audit", "logging", "accountability"],
    "assessment and authorization": ["assessment", "authorization", "security assessment"],
    "configuration management": ["configuration management", "change management", "baseline"],
    "contingency planning": ["contingency", "disaster recovery", "business continuity", "bcdr"],
    "identification and authentication": ["authentication", "identity", "mfa", "sso"],
    "incident response": ["incident response", "incident management", "security incident"],
    "maintenance": ["maintenance", "system maintenance"],
    "media protection": ["media protection", "media handling", "data disposal"],
    "physical and environmental protection": ["physical security", "physical access", "environmental"],
    "planning": ["security planning", "security plan", "system security plan"],
    "program management": ["information security program", "security program", "issp"],
    "personnel security": ["personnel security", "employee security", "onboarding", "offboarding"],
    "risk assessment": ["risk assessment", "risk management", "risk analysis"],
    "system and services acquisition": ["acquisition", "vendor management", "procurement"],
    "system and communications protection": ["communications protection", "encryption", "network security"],
    "system and information integrity": ["system integrity", "information integrity", "malware"],
    "supply chain risk management": ["supply chain", "vendor risk", "third party"],
}

# Staleness threshold — policies not updated in this many days are considered stale
STALE_THRESHOLD_DAYS = 365


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class PolicyStatus:
    """Status of a single governance document."""

    page_title: str
    page_id: str
    last_modified: datetime | None
    is_stale: bool
    is_reviewed: bool
    matched_policy_areas: list[str] = field(default_factory=list)
    days_since_modified: int | None = None


@dataclass
class PolicyGap:
    """A missing, stale, or unreviewed required policy."""

    control_id: str
    required_document: str
    status: str  # "missing", "stale", "unreviewed"
    details: str = ""


@dataclass
class CoverageScore:
    """Policy coverage metrics for a framework."""

    framework: str
    total_required: int
    covered: int
    current: int
    reviewed: int
    coverage_pct: float
    current_pct: float
    reviewed_pct: float


# ---------------------------------------------------------------------------
# GovernanceAnalyzer
# ---------------------------------------------------------------------------


class GovernanceAnalyzer:
    """Analyzes governance document content beyond mere existence checks."""

    @staticmethod
    def _get_confluence_findings(session: Session) -> list[Finding]:
        """Retrieve all Confluence page findings from the database."""
        return (
            session.query(Finding)
            .filter(
                Finding.source == "confluence",
                Finding.resource_type == "grc_document",
                Finding.observation_type == "inventory",
            )
            .all()
        )

    @staticmethod
    def _parse_last_modified(detail: dict) -> datetime | None:
        """Extract and parse the last_modified timestamp from finding detail."""
        modified_str = detail.get("last_modified", "")
        if not modified_str:
            return None
        try:
            cleaned = modified_str.replace("Z", "+00:00")
            return datetime.fromisoformat(cleaned)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _is_reviewed(detail: dict) -> bool:
        """Determine if the page has been reviewed/approved.

        Looks for approval metadata in the finding detail -- the Confluence
        normalizer may populate ``approval_status``, ``approved_by``, or
        ``review_status`` fields depending on the Confluence API data
        available.
        """
        if detail.get("approved_by"):
            return True
        if detail.get("approval_status") in ("approved", "reviewed", "current"):
            return True
        if detail.get("review_status") in ("approved", "reviewed", "current"):
            return True
        # Check for version message indicating review
        status = detail.get("status", "")
        if status == "approved":
            return True
        return False

    @staticmethod
    def _match_policy_areas(title: str) -> list[str]:
        """Match a page title against known policy area keywords."""
        title_lower = title.lower()
        matched = []
        for area, keywords in _POLICY_KEYWORDS.items():
            if any(kw in title_lower for kw in keywords):
                matched.append(area)
        return matched

    def analyze_policy_content(self, session: Session) -> list[PolicyStatus]:
        """Analyze all Confluence page findings for governance quality.

        For each page:
        - Check ``last_modified`` date (stale if >365 days old)
        - Match title against required policy areas
        - Check for approval/review metadata
        """
        findings = self._get_confluence_findings(session)
        now = datetime.now(timezone.utc)
        stale_cutoff = now - timedelta(days=STALE_THRESHOLD_DAYS)

        results: list[PolicyStatus] = []

        for finding in findings:
            detail = finding.detail if isinstance(finding.detail, dict) else {}
            title = detail.get("title", finding.resource_name or "")
            page_id = detail.get("page_id", "")

            last_modified = self._parse_last_modified(detail)
            is_stale = last_modified is not None and last_modified < stale_cutoff
            is_reviewed = self._is_reviewed(detail)
            matched_areas = self._match_policy_areas(title)

            days_since = None
            if last_modified:
                days_since = (now - last_modified).days

            results.append(PolicyStatus(
                page_title=title,
                page_id=page_id,
                last_modified=last_modified,
                is_stale=is_stale,
                is_reviewed=is_reviewed,
                matched_policy_areas=matched_areas,
                days_since_modified=days_since,
            ))

        log.info(
            "Governance analysis complete: %d documents analyzed, %d stale, %d reviewed",
            len(results),
            sum(1 for r in results if r.is_stale),
            sum(1 for r in results if r.is_reviewed),
        )

        return results

    def score_policy_coverage(
        self,
        session: Session,
        framework: str = "nist_800_53",
    ) -> CoverageScore:
        """Score policy document coverage for the given framework.

        Returns the percentage of required policy documents that:
        1. Exist (any Confluence page matches the policy area keywords)
        2. Are current (last modified within the staleness threshold)
        3. Have been reviewed/approved
        """
        policy_map = self._get_policy_map(framework)
        if not policy_map:
            return CoverageScore(
                framework=framework,
                total_required=0,
                covered=0,
                current=0,
                reviewed=0,
                coverage_pct=0.0,
                current_pct=0.0,
                reviewed_pct=0.0,
            )

        statuses = self.analyze_policy_content(session)

        # Build a set of all policy areas that are covered by existing docs
        total_required = 0
        covered = 0
        current = 0
        reviewed = 0

        for _control_id, required_docs in policy_map.items():
            for required_doc in required_docs:
                total_required += 1
                required_lower = required_doc.lower()

                # Find a matching status entry
                matching = [
                    s for s in statuses
                    if any(
                        kw in required_lower
                        for area in s.matched_policy_areas
                        for kw in [area]
                    )
                    or required_lower in s.page_title.lower()
                ]

                if matching:
                    covered += 1
                    # Use the best (most recently modified) match
                    best = max(
                        matching,
                        key=lambda s: s.last_modified or datetime.min.replace(tzinfo=timezone.utc),
                    )
                    if not best.is_stale:
                        current += 1
                    if best.is_reviewed:
                        reviewed += 1

        return CoverageScore(
            framework=framework,
            total_required=total_required,
            covered=covered,
            current=current,
            reviewed=reviewed,
            coverage_pct=round(covered / total_required * 100, 1) if total_required else 0.0,
            current_pct=round(current / total_required * 100, 1) if total_required else 0.0,
            reviewed_pct=round(reviewed / total_required * 100, 1) if total_required else 0.0,
        )

    def identify_policy_gaps(
        self,
        session: Session,
        framework: str = "nist_800_53",
    ) -> list[PolicyGap]:
        """Identify missing, stale, or unreviewed required policy documents."""
        policy_map = self._get_policy_map(framework)
        if not policy_map:
            return []

        statuses = self.analyze_policy_content(session)
        gaps: list[PolicyGap] = []

        for control_id, required_docs in policy_map.items():
            for required_doc in required_docs:
                required_lower = required_doc.lower()

                # Find matching documents
                matching = [
                    s for s in statuses
                    if any(
                        kw in required_lower
                        for area in s.matched_policy_areas
                        for kw in [area]
                    )
                    or required_lower in s.page_title.lower()
                ]

                if not matching:
                    gaps.append(PolicyGap(
                        control_id=control_id,
                        required_document=required_doc,
                        status="missing",
                        details=f"No Confluence page found matching '{required_doc}'",
                    ))
                    continue

                best = max(
                    matching,
                    key=lambda s: s.last_modified or datetime.min.replace(tzinfo=timezone.utc),
                )

                if best.is_stale:
                    gaps.append(PolicyGap(
                        control_id=control_id,
                        required_document=required_doc,
                        status="stale",
                        details=(
                            f"Document '{best.page_title}' last modified "
                            f"{best.days_since_modified} days ago"
                        ),
                    ))

                if not best.is_reviewed:
                    gaps.append(PolicyGap(
                        control_id=control_id,
                        required_document=required_doc,
                        status="unreviewed",
                        details=f"Document '{best.page_title}' has no approval/review metadata",
                    ))

        log.info(
            "Policy gap analysis for %s: %d gaps found (%d missing, %d stale, %d unreviewed)",
            framework,
            len(gaps),
            sum(1 for g in gaps if g.status == "missing"),
            sum(1 for g in gaps if g.status == "stale"),
            sum(1 for g in gaps if g.status == "unreviewed"),
        )

        return gaps

    @staticmethod
    def _get_policy_map(framework: str) -> dict[str, list[str]]:
        """Return the policy-to-control mapping for the given framework.

        Currently supports NIST 800-53 "-1" controls.  Additional frameworks
        can be added by extending this method.
        """
        if framework in ("nist_800_53", "nist-800-53", "nist"):
            return NIST_POLICY_MAP
        log.warning("No policy map defined for framework '%s'", framework)
        return {}
