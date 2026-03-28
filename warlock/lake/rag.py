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

try:
    import faiss
    import numpy as np

    _HAS_FAISS = True
except ImportError:
    _HAS_FAISS = False

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
        self._vector_store = VectorStore()

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

        # Build vector store (uses FAISS if available, else brute-force)
        self._vector_store.build(self._documents, self._tfidf_index)

        self._doc_count = len(self._documents)
        log.info(
            "RAG index built: %d documents (backend=%s)",
            self._doc_count,
            self._vector_store.backend,
        )
        return self._doc_count

    def query(self, query_text: str, top_k: int = 10) -> list[RAGResult]:
        """Search the index for documents matching the query.

        Uses FAISS vector search when available, falling back to TF-IDF
        cosine similarity.
        """
        if not self._documents:
            return []

        query_terms = _tokenize(query_text)
        if not query_terms:
            return []

        # Use vector store for search (FAISS or brute-force TF-IDF)
        scored = self._vector_store.search(query_terms, top_k)

        # Return results
        results = []
        for doc_idx, score in scored:
            if doc_idx < len(self._documents):
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


# ---------------------------------------------------------------------------
# Vector store — optional FAISS backend, falls back to TF-IDF
# ---------------------------------------------------------------------------


class VectorStore:
    """Sparse-to-dense vector store with optional FAISS acceleration.

    When FAISS is available, builds a dense index for fast approximate
    nearest-neighbor search. Otherwise falls back to brute-force TF-IDF
    cosine similarity (the existing default).
    """

    def __init__(self) -> None:
        self._use_faiss = _HAS_FAISS
        self._index: Any = None  # faiss.IndexFlatIP when available
        self._dimension: int = 0
        self._vocabulary: dict[str, int] = {}
        self._doc_vectors: list[dict[int, float]] = []

    @property
    def backend(self) -> str:
        return "faiss" if self._use_faiss and self._index is not None else "tfidf"

    def build(
        self,
        documents: list[RAGDocument],
        tfidf_index: dict[str, dict[int, float]],
    ) -> None:
        """Build the vector index from TF-IDF data.

        If FAISS is available, converts sparse TF-IDF vectors to dense
        and indexes them. Otherwise stores sparse vectors for brute-force.
        """
        if not documents or not tfidf_index:
            return

        # Build vocabulary mapping
        self._vocabulary = {term: idx for idx, term in enumerate(tfidf_index.keys())}
        self._dimension = len(self._vocabulary)

        if self._use_faiss and self._dimension > 0:
            self._build_faiss(documents, tfidf_index)
        else:
            # Store sparse vectors for brute-force fallback
            self._doc_vectors = []
            for doc_idx in range(len(documents)):
                vec: dict[int, float] = {}
                for term, term_idx in self._vocabulary.items():
                    score = tfidf_index.get(term, {}).get(doc_idx, 0.0)
                    if score > 0:
                        vec[term_idx] = score
                self._doc_vectors.append(vec)

    def _build_faiss(
        self,
        documents: list[RAGDocument],
        tfidf_index: dict[str, dict[int, float]],
    ) -> None:
        """Build FAISS index from TF-IDF vectors."""
        n_docs = len(documents)
        dim = self._dimension

        # Convert sparse TF-IDF to dense matrix
        matrix = np.zeros((n_docs, dim), dtype=np.float32)
        for term, postings in tfidf_index.items():
            term_idx = self._vocabulary[term]
            for doc_idx, score in postings.items():
                matrix[doc_idx, term_idx] = score

        # L2-normalize for cosine similarity via inner product
        norms = np.linalg.norm(matrix, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        matrix = matrix / norms

        self._index = faiss.IndexFlatIP(dim)  # type: ignore[union-attr]
        self._index.add(matrix)  # type: ignore[union-attr]
        log.info("FAISS index built: %d docs, %d dimensions", n_docs, dim)

    def search(
        self,
        query_terms: list[str],
        top_k: int = 10,
    ) -> list[tuple[int, float]]:
        """Search for similar documents. Returns (doc_idx, score) pairs."""
        if self._use_faiss and self._index is not None:
            return self._search_faiss(query_terms, top_k)
        return self._search_brute(query_terms, top_k)

    def _search_faiss(
        self,
        query_terms: list[str],
        top_k: int,
    ) -> list[tuple[int, float]]:
        """Search using FAISS inner product."""
        query_vec = np.zeros((1, self._dimension), dtype=np.float32)
        for term in query_terms:
            if term in self._vocabulary:
                query_vec[0, self._vocabulary[term]] = 1.0

        # Normalize query vector
        norm = np.linalg.norm(query_vec)
        if norm > 0:
            query_vec = query_vec / norm

        k = min(top_k, self._index.ntotal)  # type: ignore[union-attr]
        if k == 0:
            return []

        scores, indices = self._index.search(query_vec, k)  # type: ignore[union-attr]
        results = []
        for i in range(k):
            idx = int(indices[0][i])
            score = float(scores[0][i])
            if score > 0 and idx >= 0:
                results.append((idx, score))
        return results

    def _search_brute(
        self,
        query_terms: list[str],
        top_k: int,
    ) -> list[tuple[int, float]]:
        """Brute-force search over sparse TF-IDF vectors."""
        query_indices = {self._vocabulary[t] for t in query_terms if t in self._vocabulary}
        if not query_indices:
            return []

        scores: list[tuple[int, float]] = []
        for doc_idx, vec in enumerate(self._doc_vectors):
            score = sum(vec.get(qi, 0.0) for qi in query_indices)
            if score > 0:
                scores.append((doc_idx, score))

        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:top_k]
