"""Conversational compliance query engine.

Answers natural language compliance questions by querying the lake
curated zone. Routes questions to appropriate lake reader methods
based on keyword detection. When AI is disabled, performs keyword-based
SQL queries against the lake to return question-specific results.
"""

from __future__ import annotations

import logging
from pathlib import Path
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


def _extract_keywords(question: str) -> list[str]:
    """Extract meaningful keywords from a question for SQL LIKE filtering."""
    stop_words = {
        "a",
        "an",
        "the",
        "is",
        "are",
        "was",
        "were",
        "be",
        "been",
        "being",
        "have",
        "has",
        "had",
        "do",
        "does",
        "did",
        "will",
        "would",
        "could",
        "should",
        "may",
        "might",
        "shall",
        "can",
        "what",
        "which",
        "who",
        "whom",
        "how",
        "many",
        "much",
        "where",
        "when",
        "why",
        "that",
        "this",
        "these",
        "those",
        "i",
        "me",
        "my",
        "we",
        "our",
        "you",
        "your",
        "it",
        "its",
        "they",
        "them",
        "their",
        "of",
        "in",
        "on",
        "at",
        "to",
        "for",
        "with",
        "about",
        "from",
        "by",
        "as",
        "into",
        "through",
        "and",
        "or",
        "but",
        "not",
        "no",
        "any",
        "all",
        "each",
        "show",
        "tell",
        "list",
        "find",
        "get",
        "give",
        "display",
    }
    words = question.lower().split()
    return [w.strip("?.,!") for w in words if w.strip("?.,!") not in stop_words and len(w) > 2]


def query_lake(lake_path: str, question: str) -> dict[str, Any]:
    """Answer a compliance question using lake data.

    Uses intent classification to route to the appropriate lake query.
    Passes the original question through so keyword-based searches can
    filter results based on what the user actually asked.

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
    result = handler(lake_path, question)
    result["intent"] = intent
    return result


def _query_posture(lake_path: str, question: str) -> dict[str, Any]:
    """Query compliance posture, optionally filtered by framework keywords."""
    from warlock.lake.readers import LakeReaders

    keywords = _extract_keywords(question)
    readers = LakeReaders(lake_path)
    try:
        summary = readers.dashboard_framework_summary()
        frameworks = readers.distinct_frameworks()

        # Filter by any framework keywords found in the question
        fw_keywords = [k for k in keywords if any(k in fw.lower() for fw in frameworks)]
        if fw_keywords:
            summary = [r for r in summary if any(k in r[0].lower() for k in fw_keywords)]
            frameworks = [fw for fw in frameworks if any(k in fw.lower() for k in fw_keywords)]

        total = sum(r[2] for r in summary)
        compliant = sum(r[2] for r in summary if r[1] == "compliant")
        non_compliant = sum(r[2] for r in summary if r[1] == "non_compliant")
        pct = round(compliant * 100 / total, 1) if total else 0

        fw_label = ", ".join(frameworks[:5]) if frameworks else "all"
        if len(frameworks) > 5:
            fw_label += f" (+{len(frameworks) - 5} more)"

        answer_parts = [
            f"Frameworks: {fw_label}",
            f"Total assessments: {total:,}",
            f"Compliant: {compliant:,} ({pct}%)",
            f"Non-compliant: {non_compliant:,}",
        ]
        return {
            "type": "posture_summary",
            "frameworks": len(frameworks),
            "total_assessments": total,
            "compliant_pct": pct,
            "details": summary[:20],
            "answer": " | ".join(answer_parts),
        }
    finally:
        readers.close()


def _query_findings(lake_path: str, question: str) -> dict[str, Any]:
    """Search findings, filtering by keywords from the question."""
    keywords = _extract_keywords(question)
    base = Path(lake_path)
    findings_glob = str(base / "enrichment" / "**" / "*.parquet")

    if not list(base.glob("enrichment/**/*.parquet")):
        return {
            "type": "findings_summary",
            "answer": "No findings data in lake. Run pipeline with lake enabled first.",
        }

    try:
        from warlock.lake.query import LakeQueryEngine

        engine = LakeQueryEngine(lake_path)
        try:
            # Build keyword filter for title/detail/resource_id columns
            where_clauses = []
            params: list[Any] = []
            for kw in keywords[:5]:  # limit to 5 keywords
                where_clauses.append(
                    "(LOWER(title) LIKE ? OR LOWER(CAST(detail AS VARCHAR)) LIKE ?"
                    " OR LOWER(source) LIKE ?)"
                )
                like_val = f"%{kw}%"
                params.extend([like_val, like_val, like_val])

            where = ""
            if where_clauses:
                where = "WHERE " + " OR ".join(where_clauses)

            result = engine.query(
                f"""
                SELECT id, title, severity, source, resource_id, observed_at
                FROM read_parquet('{findings_glob}', union_by_name=true)
                {where}
                ORDER BY severity DESC, observed_at DESC
                LIMIT 25
                """,
                params or None,
            )

            # Also get severity breakdown
            severity_result = engine.query(
                f"""
                SELECT severity, COUNT(*) as cnt
                FROM read_parquet('{findings_glob}', union_by_name=true)
                {where}
                GROUP BY severity
                ORDER BY cnt DESC
                """,
                params or None,
            )

            severity_summary = ", ".join(f"{r['severity']}: {r['cnt']}" for r in severity_result)
            match_count = sum(r["cnt"] for r in severity_result)

            answer_parts = [f"Found {match_count} matching findings"]
            if severity_summary:
                answer_parts.append(f"By severity: {severity_summary}")
            if result:
                top = result[0]
                answer_parts.append(
                    f"Top match: {top.get('title', 'N/A')} ({top.get('severity', 'N/A')})"
                )

            return {
                "type": "findings_search",
                "match_count": match_count,
                "severity_breakdown": severity_result,
                "top_results": result[:10],
                "answer": " | ".join(answer_parts),
            }
        finally:
            engine.close()
    except ImportError:
        # Fallback if duckdb not available
        from warlock.lake.readers import LakeReaders

        readers = LakeReaders(lake_path)
        try:
            critical = readers.findings_by_severity("critical", limit=100)
            high = readers.findings_by_severity("high", limit=100)
            return {
                "type": "findings_summary",
                "critical_count": len(critical),
                "high_count": len(high),
                "answer": (
                    f"Found {len(critical)} critical and {len(high)} high severity findings."
                ),
            }
        finally:
            readers.close()


def _query_connectors(lake_path: str, question: str) -> dict[str, Any]:
    """Query connector info, filtered by keywords from the question."""
    keywords = _extract_keywords(question)
    base = Path(lake_path)
    conn_glob = str(base / "curated" / "connector_runs" / "**" / "*.parquet")

    if not list(base.glob("curated/connector_runs/**/*.parquet")):
        return {
            "type": "connector_summary",
            "answer": "No connector data in lake. Run pipeline with lake enabled first.",
        }

    try:
        from warlock.lake.query import LakeQueryEngine

        engine = LakeQueryEngine(lake_path)
        try:
            where_clauses = []
            params: list[Any] = []
            for kw in keywords[:5]:
                where_clauses.append(
                    "(LOWER(connector_name) LIKE ? OR LOWER(source) LIKE ?"
                    " OR LOWER(provider) LIKE ?)"
                )
                like_val = f"%{kw}%"
                params.extend([like_val, like_val, like_val])

            where = ""
            if where_clauses:
                where = "WHERE " + " OR ".join(where_clauses)

            result = engine.query(
                f"""
                SELECT connector_name, source, provider, status,
                       event_count, duration_seconds, started_at
                FROM read_parquet('{conn_glob}', union_by_name=true)
                {where}
                ORDER BY started_at DESC
                LIMIT 25
                """,
                params or None,
            )

            total_events = sum(r.get("event_count", 0) for r in result)
            unique_connectors = len({r["connector_name"] for r in result})

            answer = (
                f"{unique_connectors} connectors matched, {total_events:,} total events collected."
            )
            if result:
                top = result[0]
                answer += (
                    f" Most recent: {top['connector_name']} "
                    f"({top['status']}, {top.get('event_count', 0)} events)"
                )

            return {
                "type": "connector_search",
                "connector_count": unique_connectors,
                "total_events": total_events,
                "top_results": result[:10],
                "answer": answer,
            }
        finally:
            engine.close()
    except ImportError:
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


def _query_frameworks(lake_path: str, question: str) -> dict[str, Any]:
    """Query framework info, filtering by framework name keywords."""
    keywords = _extract_keywords(question)
    base = Path(lake_path)
    cr_glob = str(base / "curated" / "control_results" / "**" / "*.parquet")

    if not list(base.glob("curated/control_results/**/*.parquet")):
        return {
            "type": "framework_summary",
            "answer": "No control results in lake. Run pipeline with lake enabled first.",
        }

    try:
        from warlock.lake.query import LakeQueryEngine

        engine = LakeQueryEngine(lake_path)
        try:
            # Get per-framework breakdown (OR between keywords for broad matching)
            where_clauses = []
            params: list[Any] = []
            for kw in keywords[:5]:
                where_clauses.append("(LOWER(framework) LIKE ? OR LOWER(control_id) LIKE ?)")
                like_val = f"%{kw}%"
                params.extend([like_val, like_val])

            where = ""
            if where_clauses:
                where = "WHERE " + " OR ".join(where_clauses)

            result = engine.query(
                f"""
                SELECT framework, status, COUNT(*) as cnt
                FROM read_parquet('{cr_glob}', union_by_name=true)
                {where}
                GROUP BY framework, status
                ORDER BY framework, cnt DESC
                """,
                params or None,
            )

            # Build per-framework summary
            fw_map: dict[str, dict[str, int]] = {}
            for r in result:
                fw = r["framework"]
                if fw not in fw_map:
                    fw_map[fw] = {}
                fw_map[fw][r["status"]] = r["cnt"]

            fw_summaries = []
            for fw, statuses in sorted(fw_map.items()):
                total = sum(statuses.values())
                comp = statuses.get("compliant", 0)
                pct = round(comp * 100 / total, 1) if total else 0
                fw_summaries.append(f"{fw}: {comp}/{total} ({pct}%)")

            answer = f"Tracking {len(fw_map)} frameworks. "
            if fw_summaries:
                answer += " | ".join(fw_summaries[:8])
                if len(fw_summaries) > 8:
                    answer += f" (+{len(fw_summaries) - 8} more)"

            return {
                "type": "framework_detail",
                "framework_count": len(fw_map),
                "framework_breakdown": fw_map,
                "answer": answer,
            }
        finally:
            engine.close()
    except ImportError:
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
                "answer": (f"Tracking {len(frameworks)} frameworks: {', '.join(names)}{suffix}."),
            }
        finally:
            readers.close()


def _query_general(lake_path: str, question: str) -> dict[str, Any]:
    """General keyword search across all lake zones."""
    keywords = _extract_keywords(question)
    base = Path(lake_path)

    # Try findings first (most common search target)
    findings_glob = str(base / "enrichment" / "**" / "*.parquet")
    cr_glob = str(base / "curated" / "control_results" / "**" / "*.parquet")

    has_findings = bool(list(base.glob("enrichment/**/*.parquet")))
    has_results = bool(list(base.glob("curated/control_results/**/*.parquet")))

    if not has_findings and not has_results:
        return {
            "type": "general_overview",
            "answer": "Lake is empty. Run pipeline with WLK_LAKE_ENABLED=true first.",
        }

    try:
        from warlock.lake.query import LakeQueryEngine

        engine = LakeQueryEngine(lake_path)
        try:
            parts = []

            # Get overall stats
            if has_results:
                stats = engine.query(
                    f"""
                    SELECT COUNT(*) as total,
                           COUNT(DISTINCT framework) as fw_count
                    FROM read_parquet('{cr_glob}', union_by_name=true)
                    """
                )
                if stats:
                    parts.append(
                        f"{stats[0]['fw_count']} frameworks, {stats[0]['total']:,} assessments"
                    )

            if has_findings:
                fstats = engine.query(
                    f"""
                    SELECT COUNT(*) as total,
                           COUNT(DISTINCT source) as source_count
                    FROM read_parquet('{findings_glob}', union_by_name=true)
                    """
                )
                if fstats:
                    parts.append(
                        f"{fstats[0]['total']:,} findings from {fstats[0]['source_count']} sources"
                    )

            # Keyword search across findings if keywords present
            if keywords and has_findings:
                where_clauses = []
                params: list[Any] = []
                for kw in keywords[:3]:
                    where_clauses.append("(LOWER(title) LIKE ? OR LOWER(source) LIKE ?)")
                    like_val = f"%{kw}%"
                    params.extend([like_val, like_val])

                if where_clauses:
                    where = "WHERE " + " OR ".join(where_clauses)
                    matches = engine.query(
                        f"""
                        SELECT COUNT(*) as cnt
                        FROM read_parquet('{findings_glob}', union_by_name=true)
                        {where}
                        """,
                        params,
                    )
                    if matches and matches[0]["cnt"] > 0:
                        parts.append(
                            f"{matches[0]['cnt']} findings match '{' '.join(keywords[:3])}'"
                        )

            answer = (
                "Warlock lake: " + " | ".join(parts)
                if parts
                else "Lake has data but no matches for your query."
            )
            return {
                "type": "general_overview",
                "answer": answer,
            }
        finally:
            engine.close()
    except ImportError:
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
                "answer": (
                    f"Warlock lake: {len(frameworks)} frameworks, "
                    f"{total_assessments} assessments, {total_events} events."
                ),
            }
        finally:
            readers.close()
