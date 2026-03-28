"""Conversational compliance query engine.

Answers natural language compliance questions by querying the lake
curated zone. Routes questions to appropriate lake reader methods
based on keyword detection.
"""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)


def classify_intent(query: str) -> str:
    """Classify NL query intent using keyword + pattern matching.

    Scores each intent category and returns the highest-scoring one.
    This is a basic improvement over pure keyword matching -- actual LLM
    classification is future work (requires ai_enabled=true).
    """
    query_lower = query.lower()

    patterns: dict[str, list[str]] = {
        "compliance_status": [
            "compliance",
            "status",
            "score",
            "posture",
            "ready",
            "compliant",
            "passing",
            "failing",
            "gap",
            "coverage",
        ],
        "finding_search": [
            "finding",
            "vulnerability",
            "issue",
            "cve",
            "misconfiguration",
            "alert",
            "critical",
            "severity",
        ],
        "risk_analysis": [
            "risk",
            "exposure",
            "ale",
            "probability",
            "impact",
            "threat",
            "likelihood",
            "residual",
        ],
        "trend": [
            "trend",
            "over time",
            "history",
            "change",
            "delta",
            "regression",
            "improving",
            "worsening",
        ],
        "connector_info": [
            "connector",
            "source",
            "collection",
            "ingestion",
            "integration",
            "data source",
        ],
        "framework_info": [
            "framework",
            "control",
            "nist",
            "soc",
            "iso",
            "hipaa",
            "pci",
            "gdpr",
            "fedramp",
            "cmmc",
        ],
    }

    scores: dict[str, float] = {}
    for intent, keywords in patterns.items():
        score = 0.0
        for kw in keywords:
            if kw in query_lower:
                # Multi-word patterns get a bonus for specificity
                score += 1.0 + (0.5 * (kw.count(" ")))
        scores[intent] = score

    best = max(scores, key=scores.get)  # type: ignore[arg-type]
    if scores[best] == 0:
        return "general"
    return best


def query_lake(lake_path: str, question: str) -> dict[str, Any]:
    """Answer a compliance question using lake data.

    Uses intent classification to route to the appropriate lake query.
    Returns structured data with an 'answer' field.
    """
    intent = classify_intent(question)
    log.debug("NL query intent=%s for question=%r", intent, question[:80])

    _INTENT_HANDLERS: dict[str, str] = {
        "compliance_status": "_query_posture",
        "finding_search": "_query_findings",
        "risk_analysis": "_query_findings",
        "trend": "_query_posture",
        "connector_info": "_query_connectors",
        "framework_info": "_query_frameworks",
        "general": "_query_general",
    }

    handler_name = _INTENT_HANDLERS.get(intent, "_query_general")
    handler = globals()[handler_name]
    result = handler(lake_path)
    result["intent"] = intent
    return result


def _query_posture(lake_path: str) -> dict[str, Any]:
    from warlock.lake.readers import LakeReaders

    readers = LakeReaders(lake_path)
    try:
        summary = readers.dashboard_framework_summary()
        frameworks = readers.distinct_frameworks()
        total = sum(r[2] for r in summary)
        compliant = sum(r[2] for r in summary if r[1] == "compliant")
        pct = round(compliant * 100 / total, 1) if total else 0
        return {
            "type": "posture_summary",
            "frameworks": len(frameworks),
            "total_assessments": total,
            "compliant_pct": pct,
            "answer": f"Tracking {len(frameworks)} frameworks with {total} control assessments. Overall compliance: {pct}%.",
        }
    finally:
        readers.close()


def _query_findings(lake_path: str) -> dict[str, Any]:
    from warlock.lake.readers import LakeReaders

    readers = LakeReaders(lake_path)
    try:
        critical = readers.findings_by_severity("critical", limit=100)
        high = readers.findings_by_severity("high", limit=100)
        return {
            "type": "findings_summary",
            "critical_count": len(critical),
            "high_count": len(high),
            "answer": f"Found {len(critical)} critical and {len(high)} high severity findings.",
        }
    finally:
        readers.close()


def _query_connectors(lake_path: str) -> dict[str, Any]:
    from warlock.lake.readers import LakeReaders

    readers = LakeReaders(lake_path)
    try:
        connectors = readers.latest_per_connector()
        total = readers.total_event_count()
        return {
            "type": "connector_summary",
            "connector_count": len(connectors),
            "total_events": total,
            "answer": f"{len(connectors)} connectors collected {total} total events.",
        }
    finally:
        readers.close()


def _query_frameworks(lake_path: str) -> dict[str, Any]:
    from warlock.lake.readers import LakeReaders

    readers = LakeReaders(lake_path)
    try:
        frameworks = readers.list_frameworks()
        names = [f[0] for f in frameworks[:5]]
        suffix = f" and {len(frameworks) - 5} more" if len(frameworks) > 5 else ""
        return {
            "type": "framework_summary",
            "framework_count": len(frameworks),
            "frameworks": frameworks,
            "answer": f"Tracking {len(frameworks)} frameworks: {', '.join(names)}{suffix}.",
        }
    finally:
        readers.close()


def _query_general(lake_path: str) -> dict[str, Any]:
    from warlock.lake.readers import LakeReaders

    readers = LakeReaders(lake_path)
    try:
        summary = readers.dashboard_framework_summary()
        frameworks = readers.distinct_frameworks()
        total_events = readers.total_event_count()
        total_assessments = sum(r[2] for r in summary)
        return {
            "type": "general_overview",
            "frameworks": len(frameworks),
            "total_assessments": total_assessments,
            "total_events": total_events,
            "answer": f"Warlock lake: {len(frameworks)} frameworks, {total_assessments} assessments, {total_events} events.",
        }
    finally:
        readers.close()
