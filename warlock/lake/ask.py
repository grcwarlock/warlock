"""Conversational compliance query engine.

Answers natural language compliance questions by querying the lake
curated zone. Routes questions to appropriate lake reader methods
based on keyword detection.
"""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)


def query_lake(lake_path: str, question: str) -> dict[str, Any]:
    """Answer a compliance question using lake data.

    Routes to appropriate lake query based on question keywords.
    Returns structured data with an 'answer' field.
    """
    question_lower = question.lower()

    if any(kw in question_lower for kw in ["posture", "compliance", "status", "ready"]):
        return _query_posture(lake_path)
    elif any(kw in question_lower for kw in ["finding", "vulnerability", "risk"]):
        return _query_findings(lake_path)
    elif any(kw in question_lower for kw in ["connector", "source", "collection"]):
        return _query_connectors(lake_path)
    elif any(kw in question_lower for kw in ["framework", "control"]):
        return _query_frameworks(lake_path)
    else:
        return _query_general(lake_path)


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
