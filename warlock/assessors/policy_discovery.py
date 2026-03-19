"""Policy document discovery and coverage analysis.

Scans Confluence-sourced findings for policy documents, maps them to
compliance framework controls using the RAG semantic matcher, and
scores policy documentation coverage.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import distinct
from sqlalchemy.orm import Session

from warlock.db.models import (
    ControlMapping,
    ControlResult,
    Finding,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class DiscoveredPolicy:
    """A policy document discovered from Confluence or other GRC sources."""

    title: str
    last_updated: datetime | None = None
    author: str = ""
    url: str = ""
    source_finding_id: str = ""
    content_summary: str = ""
    matched_controls: list[str] = field(default_factory=list)


@dataclass
class PolicyCoverageScore:
    """Policy documentation coverage for a framework."""

    framework: str
    total_controls: int
    controls_with_policy: int
    coverage_pct: float  # 0-100
    gaps: list[str] = field(default_factory=list)
    policy_map: dict[str, list[str]] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Policy keywords for heuristic matching (fallback when RAG is unavailable)
# ---------------------------------------------------------------------------

_POLICY_KEYWORDS: dict[str, list[str]] = {
    "AC": ["access control", "access management", "authentication", "authorization",
           "least privilege", "account management", "session", "login"],
    "AU": ["audit", "logging", "monitoring", "log review", "event logging",
           "audit trail", "accountability"],
    "CM": ["configuration", "change management", "baseline", "configuration management",
           "hardening", "patching", "change control"],
    "CP": ["contingency", "backup", "disaster recovery", "business continuity",
           "incident recovery", "continuity of operations"],
    "IA": ["identification", "authentication", "identity", "credential",
           "multi-factor", "mfa", "password"],
    "IR": ["incident response", "incident handling", "incident management",
           "breach response", "security incident"],
    "PE": ["physical", "physical security", "environmental", "facility",
           "physical access"],
    "RA": ["risk assessment", "risk management", "risk analysis",
           "threat assessment", "vulnerability assessment"],
    "SA": ["acquisition", "supply chain", "vendor", "third-party",
           "procurement", "service provider"],
    "SC": ["system communications", "encryption", "cryptography", "network",
           "data protection", "boundary protection", "firewall"],
    "SI": ["system integrity", "malware", "flaw remediation", "vulnerability",
           "antivirus", "intrusion detection", "patching"],
    "SR": ["supply chain risk", "vendor risk", "third-party risk",
           "supplier", "supply chain management"],
}

# Map SOC 2 Trust Service Criteria to keyword groups
_SOC2_KEYWORD_MAP: dict[str, list[str]] = {
    "CC1": ["governance", "ethics", "organizational structure", "board oversight"],
    "CC2": ["communication", "information", "reporting", "internal communication"],
    "CC3": ["risk assessment", "risk management", "risk analysis"],
    "CC4": ["monitoring", "monitoring activities", "ongoing evaluation"],
    "CC5": ["control activities", "policies", "procedures", "segregation of duties"],
    "CC6": ["access control", "authentication", "logical access", "physical access"],
    "CC7": ["system operations", "change management", "incident management"],
    "CC8": ["change management", "change control", "system changes"],
    "CC9": ["risk mitigation", "risk treatment", "vendor management"],
}


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------

def discover_policies(
    session: Session,
    source_type: str = "grc",
    resource_type: str = "grc_document",
) -> list[DiscoveredPolicy]:
    """Scan Confluence and other GRC-source findings for policy documents.

    Queries the Finding table for documents with resource_type='grc_document'
    and extracts policy metadata from finding details.

    Returns:
        List of DiscoveredPolicy objects.
    """
    findings = (
        session.query(Finding)
        .filter(
            Finding.resource_type == resource_type,
        )
        .order_by(Finding.observed_at.desc())
        .all()
    )

    if not findings:
        log.info("No policy documents found (resource_type=%s)", resource_type)
        return []

    policies: list[DiscoveredPolicy] = []
    seen_titles: set[str] = set()

    for f in findings:
        detail = f.detail or {}
        title = detail.get("title", f.title)

        # Deduplicate by title (keep most recent)
        title_key = title.lower().strip()
        if title_key in seen_titles:
            continue
        seen_titles.add(title_key)

        # Skip non-policy documents (e.g., meeting notes, templates)
        if not _is_likely_policy(title, detail):
            continue

        last_updated = None
        updated_str = detail.get("last_updated") or detail.get("modified_at")
        if updated_str and isinstance(updated_str, str):
            try:
                last_updated = datetime.fromisoformat(updated_str)
            except (ValueError, TypeError):
                pass
        if last_updated is None:
            last_updated = f.observed_at

        policies.append(DiscoveredPolicy(
            title=title,
            last_updated=last_updated,
            author=detail.get("author", ""),
            url=detail.get("url", detail.get("link", "")),
            source_finding_id=f.id,
            content_summary=detail.get("summary", detail.get("excerpt", "")),
        ))

    log.info("Discovered %d policy documents from %d findings", len(policies), len(findings))
    return policies


def match_policies_to_controls(
    policies: list[DiscoveredPolicy],
    framework: str,
    session: Session | None = None,
    use_rag: bool = True,
) -> dict[str, list[str]]:
    """Map discovered policies to the framework controls they satisfy.

    Uses the RAG semantic matcher when available; falls back to keyword
    heuristic matching.

    Args:
        policies: List of discovered policy documents.
        framework: Framework identifier (e.g., 'nist_800_53').
        session: DB session (used to get control IDs if RAG is unavailable).
        use_rag: Whether to attempt RAG-based matching.

    Returns:
        Dict mapping control_id -> list of policy titles that cover it.
    """
    control_to_policies: dict[str, list[str]] = {}
    rag_matcher = None

    # Try RAG matching first
    if use_rag:
        try:
            from warlock.assessors.rag import create_rag_matcher
            rag_matcher = create_rag_matcher()
            log.info("Using RAG matcher for policy-to-control mapping")
        except Exception as e:
            log.info("RAG matcher unavailable (%s), using keyword fallback", e)

    for policy in policies:
        matched_controls: list[str] = []

        if rag_matcher and rag_matcher.store.count() > 0:
            # Semantic matching via RAG
            query_text = f"{policy.title} {policy.content_summary}"
            matches = rag_matcher.match(
                finding_title=query_text,
                finding_detail={"description": policy.content_summary},
                top_k=5,
                min_score=0.5,
            )
            for fw, control_id, score in matches:
                if fw == framework:
                    matched_controls.append(control_id)
        else:
            # Keyword-based fallback matching
            matched_controls = _keyword_match(policy, framework)

        policy.matched_controls = matched_controls

        for control_id in matched_controls:
            control_to_policies.setdefault(control_id, [])
            if policy.title not in control_to_policies[control_id]:
                control_to_policies[control_id].append(policy.title)

    log.info(
        "Mapped %d policies to %d controls in %s",
        len(policies),
        len(control_to_policies),
        framework,
    )
    return control_to_policies


def score_policy_coverage(
    session: Session,
    framework: str,
    use_rag: bool = True,
) -> PolicyCoverageScore:
    """Score what percentage of controls have supporting policy docs.

    Discovers policies, matches them to controls, and computes coverage
    relative to the set of controls that have ControlResult rows.

    Returns:
        PolicyCoverageScore with detailed breakdown.
    """
    # Get all controls in the framework
    control_rows = (
        session.query(distinct(ControlResult.control_id))
        .filter(ControlResult.framework == framework)
        .all()
    )
    all_controls = sorted([row[0] for row in control_rows])

    if not all_controls:
        return PolicyCoverageScore(
            framework=framework,
            total_controls=0,
            controls_with_policy=0,
            coverage_pct=0.0,
            gaps=[],
        )

    # Discover and match policies
    policies = discover_policies(session)
    policy_map = match_policies_to_controls(
        policies, framework, session=session, use_rag=use_rag,
    )

    controls_covered = [
        c for c in all_controls
        if c in policy_map or any(c.startswith(family) for family in policy_map)
    ]
    gaps = [
        c for c in all_controls
        if c not in policy_map and not any(c.startswith(family) for family in policy_map)
    ]

    coverage_pct = (
        round(len(controls_covered) / len(all_controls) * 100, 2)
        if all_controls
        else 0.0
    )

    return PolicyCoverageScore(
        framework=framework,
        total_controls=len(all_controls),
        controls_with_policy=len(controls_covered),
        coverage_pct=coverage_pct,
        gaps=gaps,
        policy_map=policy_map,
    )


def identify_policy_gaps(
    session: Session,
    framework: str,
    use_rag: bool = True,
) -> list[str]:
    """Identify controls with no policy documentation.

    Convenience wrapper around score_policy_coverage.

    Returns:
        List of control IDs that lack policy documentation.
    """
    coverage = score_policy_coverage(session, framework, use_rag=use_rag)
    return coverage.gaps


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _is_likely_policy(title: str, detail: dict[str, Any]) -> bool:
    """Heuristic check: is this document likely a policy/procedure/standard?

    Looks for policy-related keywords in title, document type, or labels.
    """
    policy_indicators = {
        "policy", "procedure", "standard", "guideline", "plan",
        "framework", "handbook", "runbook", "playbook", "process",
        "control", "security", "compliance", "governance", "risk",
        "incident response", "disaster recovery", "business continuity",
        "access control", "data protection", "privacy", "acceptable use",
        "change management", "configuration management", "audit",
    }

    text = title.lower()

    # Check title
    for indicator in policy_indicators:
        if indicator in text:
            return True

    # Check document type or labels in detail
    doc_type = str(detail.get("document_type", "")).lower()
    labels = detail.get("labels", [])
    if isinstance(labels, list):
        label_text = " ".join(str(l).lower() for l in labels)
    else:
        label_text = str(labels).lower()

    for indicator in policy_indicators:
        if indicator in doc_type or indicator in label_text:
            return True

    return False


def _keyword_match(policy: DiscoveredPolicy, framework: str) -> list[str]:
    """Match a policy to controls using keyword heuristics.

    Checks the policy title and content summary against known keyword
    mappings for NIST 800-53 families and SOC 2 criteria.
    """
    text = f"{policy.title} {policy.content_summary}".lower()
    matched: list[str] = []

    # Determine which keyword map to use
    if "soc2" in framework.lower() or "soc_2" in framework.lower():
        keyword_map = _SOC2_KEYWORD_MAP
    else:
        keyword_map = _POLICY_KEYWORDS

    for family, keywords in keyword_map.items():
        for keyword in keywords:
            if keyword in text:
                matched.append(family)
                break

    return matched
