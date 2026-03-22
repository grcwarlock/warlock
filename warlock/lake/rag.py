"""RAG over the curated zone — semantic search over compliance data.

Indexes control results, findings, and framework data from the lake.
Uses TF-IDF embeddings by default (no API key needed). Can upgrade
to OpenAI/Anthropic embeddings for better quality.

Usage:
    rag = LakeRAG(lake_path)
    rag.index()  # Build index from curated zone Parquet files
    results = rag.query("access control compliance status")
"""

from __future__ import annotations

import logging
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


@dataclass
class RAGDocument:
    """A document in the RAG index."""

    id: str
    content: str
    source: str  # e.g., "control_result", "finding", "framework"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class RAGResult:
    """A search result from the RAG index."""

    document: RAGDocument
    score: float


class LakeRAG:
    """RAG engine over the lake curated zone.

    Indexes compliance data from Parquet files and provides
    semantic search using TF-IDF (no external dependencies).
    """

    def __init__(self, lake_path: str) -> None:
        self._lake_path = lake_path
        self._documents: list[RAGDocument] = []
        self._tfidf_index: dict[str, dict[int, float]] = {}  # term -> {doc_idx: tfidf}
        self._doc_count = 0

    @property
    def document_count(self) -> int:
        return len(self._documents)

    def index(self) -> int:
        """Build the RAG index from curated zone Parquet files.

        Returns the number of documents indexed.
        """
        self._documents = []

        # Index control results (compliance assessments)
        self._index_control_results()

        # Index findings (security observations)
        self._index_findings()

        # Index control mappings (framework coverage)
        self._index_control_mappings()

        # Build TF-IDF index
        self._build_tfidf()

        self._doc_count = len(self._documents)
        log.info("RAG index built: %d documents", self._doc_count)
        return self._doc_count

    def query(self, query_text: str, top_k: int = 10) -> list[RAGResult]:
        """Search the index for documents matching the query.

        Uses TF-IDF cosine similarity for ranking.
        """
        if not self._documents:
            return []

        query_terms = _tokenize(query_text)
        if not query_terms:
            return []

        # Score each document
        scores: list[tuple[int, float]] = []
        for doc_idx in range(len(self._documents)):
            score = 0.0
            for term in query_terms:
                if term in self._tfidf_index:
                    score += self._tfidf_index[term].get(doc_idx, 0.0)
            if score > 0:
                scores.append((doc_idx, score))

        # Sort by score descending
        scores.sort(key=lambda x: x[1], reverse=True)

        # Return top_k results
        results = []
        for doc_idx, score in scores[:top_k]:
            results.append(
                RAGResult(
                    document=self._documents[doc_idx],
                    score=score,
                )
            )

        return results

    def _index_control_results(self) -> None:
        """Index control results from curated zone."""
        base = Path(self._lake_path)
        parquet_files = list(base.glob("curated/control_results/**/*.parquet"))
        if not parquet_files:
            return

        try:
            from warlock.lake.query import LakeQueryEngine

            engine = LakeQueryEngine(self._lake_path)
            glob = str(base / "curated" / "control_results" / "**" / "*.parquet")
            results = engine.query(f"""
                SELECT DISTINCT framework, control_id, status, severity, assertion_name
                FROM read_parquet('{glob}', union_by_name=true)
            """)
            engine.close()

            for r in results:
                content = (
                    f"Control {r['control_id']} in {r['framework']}: "
                    f"status={r['status']}, severity={r['severity']}, "
                    f"assertion={r.get('assertion_name', 'none')}"
                )
                self._documents.append(
                    RAGDocument(
                        id=f"cr:{r['framework']}:{r['control_id']}",
                        content=content,
                        source="control_result",
                        metadata=r,
                    )
                )
        except Exception:
            log.warning("Failed to index control results for RAG")

    def _index_findings(self) -> None:
        """Index findings from enrichment zone."""
        base = Path(self._lake_path)
        if not list(base.glob("enrichment/**/*.parquet")):
            return

        try:
            from warlock.lake.query import LakeQueryEngine

            engine = LakeQueryEngine(self._lake_path)
            glob = str(base / "enrichment" / "**" / "*.parquet")
            results = engine.query(f"""
                SELECT DISTINCT id, title, severity, source, observation_type
                FROM read_parquet('{glob}', union_by_name=true)
                LIMIT 1000
            """)
            engine.close()

            for r in results:
                content = (
                    f"Finding: {r.get('title', 'Untitled')} "
                    f"(severity={r['severity']}, source={r['source']}, "
                    f"type={r.get('observation_type', 'unknown')})"
                )
                self._documents.append(
                    RAGDocument(
                        id=f"finding:{r['id']}",
                        content=content,
                        source="finding",
                        metadata=r,
                    )
                )
        except Exception:
            log.warning("Failed to index findings for RAG")

    def _index_control_mappings(self) -> None:
        """Index control mappings from curated zone."""
        base = Path(self._lake_path)
        if not list(base.glob("curated/control_mappings/**/*.parquet")):
            return

        try:
            from warlock.lake.query import LakeQueryEngine

            engine = LakeQueryEngine(self._lake_path)
            glob = str(base / "curated" / "control_mappings" / "**" / "*.parquet")
            results = engine.query(f"""
                SELECT DISTINCT framework, control_id, control_family, mapping_method
                FROM read_parquet('{glob}', union_by_name=true)
            """)
            engine.close()

            for r in results:
                content = (
                    f"Framework {r['framework']} control {r['control_id']} "
                    f"(family={r.get('control_family', '')}, "
                    f"mapped via {r.get('mapping_method', 'unknown')})"
                )
                self._documents.append(
                    RAGDocument(
                        id=f"mapping:{r['framework']}:{r['control_id']}",
                        content=content,
                        source="control_mapping",
                        metadata=r,
                    )
                )
        except Exception:
            log.warning("Failed to index control mappings for RAG")

    def _build_tfidf(self) -> None:
        """Build TF-IDF index over all documents."""
        if not self._documents:
            return

        n_docs = len(self._documents)
        # Document frequency per term
        df: Counter = Counter()
        doc_terms: list[Counter] = []

        for doc in self._documents:
            terms = Counter(_tokenize(doc.content))
            doc_terms.append(terms)
            for term in terms:
                df[term] += 1

        # Build TF-IDF vectors
        self._tfidf_index = {}
        for term, doc_freq in df.items():
            idf = math.log(n_docs / (1 + doc_freq))
            self._tfidf_index[term] = {}
            for doc_idx, terms in enumerate(doc_terms):
                if term in terms:
                    tf = terms[term] / sum(terms.values())
                    self._tfidf_index[term][doc_idx] = tf * idf


def _tokenize(text: str) -> list[str]:
    """Simple word tokenization with lowercasing and filtering."""
    words = re.findall(r"[a-z0-9_]+", text.lower())
    # Filter stopwords
    stopwords = {
        "the",
        "a",
        "an",
        "is",
        "are",
        "was",
        "were",
        "in",
        "on",
        "at",
        "to",
        "for",
        "of",
        "with",
        "by",
        "from",
        "as",
        "and",
        "or",
        "not",
        "this",
        "that",
        "it",
        "be",
        "has",
        "have",
        "had",
        "do",
        "does",
    }
    return [w for w in words if w not in stopwords and len(w) > 1]
