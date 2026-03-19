"""RAG pipeline for semantic control matching.

Embeds compliance control descriptions into a vector store and retrieves
the most relevant controls for a given finding. This serves as Tier 4
in the control mapping hierarchy — used when explicit rules, resource
rules, and crosswalks don't produce matches.

Supports multiple backends:
  - pgvector (PostgreSQL with vector extension)
  - Chroma (local/embedded vector DB)
  - In-memory FAISS (for development/testing)

Embedding providers:
  - OpenAI (text-embedding-3-small)
  - Anthropic (via Voyager)
  - Sentence Transformers (local, no API key needed)
"""

from __future__ import annotations

import logging
import math
import re
from abc import ABC, abstractmethod
from collections import Counter
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

from warlock.mappers.control_mapper import ControlMappingData
from warlock.normalizers.base import FindingData

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ControlDocument — the unit stored in the vector DB
# ---------------------------------------------------------------------------

@dataclass
class ControlDocument:
    control_id: str
    framework: str
    family: str
    title: str
    description: str
    text: str  # combined searchable text
    embedding: list[float] | None = None


# ---------------------------------------------------------------------------
# TF-IDF embedder (zero-dependency fallback)
# ---------------------------------------------------------------------------

_STOP_WORDS = frozenset({
    "a", "an", "the", "and", "or", "but", "in", "on", "at", "to", "for",
    "of", "with", "by", "from", "is", "it", "as", "be", "was", "are",
    "been", "being", "have", "has", "had", "do", "does", "did", "will",
    "shall", "should", "may", "might", "must", "can", "could", "would",
    "that", "this", "these", "those", "not", "no", "nor", "so", "if",
    "then", "than", "too", "very", "just", "about", "above", "after",
    "again", "all", "also", "am", "any", "because", "before", "between",
    "both", "each", "few", "further", "here", "how", "into", "its",
    "more", "most", "other", "our", "out", "over", "own", "same", "some",
    "such", "there", "through", "under", "until", "up", "we", "what",
    "when", "where", "which", "while", "who", "whom", "why", "you",
    "your",
})

_TOKEN_RE = re.compile(r"[a-z0-9_]+")


def _tokenize(text: str) -> list[str]:
    """Lowercase, split on non-alphanumeric, remove stop words."""
    return [t for t in _TOKEN_RE.findall(text.lower()) if t not in _STOP_WORDS]


class TFIDFEmbedder:
    """Simple TF-IDF embedder that works with zero dependencies beyond stdlib."""

    def __init__(self) -> None:
        self._vocab: dict[str, int] = {}
        self._idf: dict[str, float] = {}
        self._fitted = False

    def fit(self, corpus: list[str]) -> None:
        """Build vocabulary and IDF weights from a corpus of documents."""
        n_docs = len(corpus)
        if n_docs == 0:
            self._fitted = True
            return

        # Count document frequency for each term
        doc_freq: Counter[str] = Counter()
        all_terms: set[str] = set()

        for text in corpus:
            tokens = set(_tokenize(text))
            doc_freq.update(tokens)
            all_terms.update(tokens)

        # Build vocabulary: assign an index to each term, sorted for determinism
        self._vocab = {term: idx for idx, term in enumerate(sorted(all_terms))}

        # Compute IDF: log(N / (df + 1)) + 1  (smoothed, scikit-learn style)
        self._idf = {
            term: math.log(n_docs / (df + 1)) + 1.0
            for term, df in doc_freq.items()
        }

        self._fitted = True

    def transform(self, texts: list[str]) -> list[list[float]]:
        """Return TF-IDF vectors for the given texts.

        Must call fit() first. Unknown terms are ignored.
        """
        if not self._fitted:
            raise RuntimeError("TFIDFEmbedder.fit() must be called before transform()")

        dim = len(self._vocab)
        if dim == 0:
            return [[0.0] for _ in texts]

        results: list[list[float]] = []
        for text in texts:
            tokens = _tokenize(text)
            tf: Counter[str] = Counter(tokens)
            vec = [0.0] * dim

            for term, count in tf.items():
                if term in self._vocab:
                    idx = self._vocab[term]
                    # Sub-linear TF: 1 + log(tf) if tf > 0
                    tf_val = 1.0 + math.log(count) if count > 0 else 0.0
                    idf_val = self._idf.get(term, 1.0)
                    vec[idx] = tf_val * idf_val

            # L2 normalize
            norm = math.sqrt(sum(v * v for v in vec))
            if norm > 1e-10:
                vec = [v / norm for v in vec]

            results.append(vec)
        return results

    def fit_transform(self, corpus: list[str]) -> list[list[float]]:
        """Convenience: fit on corpus, then transform it."""
        self.fit(corpus)
        return self.transform(corpus)


# ---------------------------------------------------------------------------
# EmbeddingProvider — abstract base + implementations
# ---------------------------------------------------------------------------

class EmbeddingProvider(ABC):
    """Base class for embedding providers."""

    @abstractmethod
    def embed(self, texts: list[str]) -> list[list[float]]:
        """Embed a batch of texts into vectors."""
        ...

    def embed_one(self, text: str) -> list[float]:
        """Embed a single text string."""
        return self.embed([text])[0]


class OpenAIEmbedder(EmbeddingProvider):
    """Calls the OpenAI embeddings API via httpx."""

    def __init__(
        self,
        api_key: str,
        model: str = "text-embedding-3-small",
        base_url: str = "https://api.openai.com/v1",
        batch_size: int = 100,
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._batch_size = batch_size

    def embed(self, texts: list[str]) -> list[list[float]]:
        import httpx

        all_embeddings: list[list[float]] = []

        for i in range(0, len(texts), self._batch_size):
            batch = texts[i : i + self._batch_size]
            resp = httpx.post(
                f"{self._base_url}/embeddings",
                headers={"Authorization": f"Bearer {self._api_key}"},
                json={"model": self._model, "input": batch},
                timeout=30.0,
            )
            resp.raise_for_status()
            data = resp.json()
            # Sort by index to guarantee order matches input
            sorted_items = sorted(data["data"], key=lambda x: x["index"])
            all_embeddings.extend(item["embedding"] for item in sorted_items)

        return all_embeddings


class LocalEmbedder(EmbeddingProvider):
    """Uses sentence-transformers if available, falls back to TF-IDF.

    The TF-IDF fallback requires no external dependencies and works in
    any Python environment. It produces lower-quality embeddings but is
    sufficient for development and testing.
    """

    def __init__(self, model_name: str = "all-MiniLM-L6-v2") -> None:
        self._st_model: Any = None
        self._tfidf: TFIDFEmbedder | None = None
        self._use_sentence_transformers = False
        self._model_name = model_name

        # Try sentence-transformers first
        try:
            from sentence_transformers import SentenceTransformer
            self._st_model = SentenceTransformer(model_name)
            self._use_sentence_transformers = True
            log.info("LocalEmbedder: using sentence-transformers (%s)", model_name)
        except ImportError:
            log.info("LocalEmbedder: sentence-transformers not installed, using TF-IDF fallback")
            self._tfidf = TFIDFEmbedder()

    @property
    def is_tfidf(self) -> bool:
        """True if using the TF-IDF fallback instead of sentence-transformers."""
        return not self._use_sentence_transformers

    def fit_tfidf(self, corpus: list[str]) -> None:
        """Fit the TF-IDF vocabulary on a corpus. Only needed for TF-IDF mode.

        For sentence-transformers this is a no-op.
        """
        if self._tfidf is not None:
            self._tfidf.fit(corpus)

    def embed(self, texts: list[str]) -> list[list[float]]:
        if self._use_sentence_transformers:
            embeddings = self._st_model.encode(texts, show_progress_bar=False)
            return [e.tolist() for e in embeddings]

        if self._tfidf is None:
            raise RuntimeError("LocalEmbedder has no backend available")

        if not self._tfidf._fitted:
            # Auto-fit on the first batch if not already fitted
            self._tfidf.fit(texts)

        return self._tfidf.transform(texts)


# ---------------------------------------------------------------------------
# VectorStore — abstract base + implementations
# ---------------------------------------------------------------------------

class VectorStore(ABC):
    """Base class for vector stores."""

    @abstractmethod
    def add(self, docs: list[ControlDocument]) -> None:
        """Add documents with precomputed embeddings to the store."""
        ...

    @abstractmethod
    def search(
        self, query_embedding: list[float], top_k: int = 5,
    ) -> list[tuple[ControlDocument, float]]:
        """Return the top-k most similar documents with their scores."""
        ...

    @abstractmethod
    def count(self) -> int:
        """Number of documents in the store."""
        ...


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    """Cosine similarity between two vectors using numpy."""
    import numpy as np

    a_arr, b_arr = np.array(a), np.array(b)
    return float(np.dot(a_arr, b_arr) / (np.linalg.norm(a_arr) * np.linalg.norm(b_arr) + 1e-10))


def _cosine_similarity_pure(a: list[float], b: list[float]) -> float:
    """Cosine similarity without numpy — stdlib-only fallback."""
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))
    return dot / (norm_a * norm_b + 1e-10)


class InMemoryStore(VectorStore):
    """In-memory vector store using cosine similarity.

    Always available — no external dependencies beyond numpy (falls back
    to pure Python if numpy is not installed). Suitable for development,
    testing, and small-to-medium control catalogs (< 10k controls).
    """

    def __init__(self) -> None:
        self._docs: list[ControlDocument] = []
        self._embeddings: list[list[float]] = []
        self._cosine_fn = _cosine_similarity
        try:
            import numpy as np  # noqa: F401
        except ImportError:
            log.debug("numpy not available, using pure-Python cosine similarity")
            self._cosine_fn = _cosine_similarity_pure

    def add(self, docs: list[ControlDocument]) -> None:
        for doc in docs:
            if doc.embedding is None:
                raise ValueError(
                    f"ControlDocument {doc.control_id} has no embedding. "
                    "Embed documents before adding to the store."
                )
            self._docs.append(doc)
            self._embeddings.append(doc.embedding)

    def search(
        self, query_embedding: list[float], top_k: int = 5,
    ) -> list[tuple[ControlDocument, float]]:
        if not self._docs:
            return []

        scored: list[tuple[ControlDocument, float]] = []
        for doc, emb in zip(self._docs, self._embeddings):
            sim = self._cosine_fn(query_embedding, emb)
            scored.append((doc, sim))

        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:top_k]

    def count(self) -> int:
        return len(self._docs)


class ChromaStore(VectorStore):
    """Vector store backed by ChromaDB.

    Requires: ``pip install chromadb``
    """

    def __init__(
        self,
        collection_name: str = "warlock_controls",
        persist_directory: str | None = None,
    ) -> None:
        import chromadb

        if persist_directory:
            self._client = chromadb.PersistentClient(path=persist_directory)
        else:
            self._client = chromadb.EphemeralClient()

        self._collection = self._client.get_or_create_collection(
            name=collection_name,
            metadata={"hnsw:space": "cosine"},
        )
        # Local cache for returning ControlDocument objects
        self._doc_map: dict[str, ControlDocument] = {}

    def add(self, docs: list[ControlDocument]) -> None:
        if not docs:
            return

        ids: list[str] = []
        embeddings: list[list[float]] = []
        documents: list[str] = []
        metadatas: list[dict[str, str]] = []

        for doc in docs:
            if doc.embedding is None:
                raise ValueError(
                    f"ControlDocument {doc.control_id} has no embedding."
                )
            doc_id = f"{doc.framework}:{doc.control_id}"
            ids.append(doc_id)
            embeddings.append(doc.embedding)
            documents.append(doc.text)
            metadatas.append({
                "framework": doc.framework,
                "control_id": doc.control_id,
                "family": doc.family,
                "title": doc.title,
            })
            self._doc_map[doc_id] = doc

        self._collection.upsert(
            ids=ids,
            embeddings=embeddings,
            documents=documents,
            metadatas=metadatas,
        )

    def search(
        self, query_embedding: list[float], top_k: int = 5,
    ) -> list[tuple[ControlDocument, float]]:
        results = self._collection.query(
            query_embeddings=[query_embedding],
            n_results=min(top_k, self._collection.count()),
        )

        if not results["ids"] or not results["ids"][0]:
            return []

        output: list[tuple[ControlDocument, float]] = []
        ids = results["ids"][0]
        # Chroma returns distances; for cosine space, similarity = 1 - distance
        distances = results["distances"][0] if results["distances"] else [0.0] * len(ids)

        for doc_id, dist in zip(ids, distances):
            doc = self._doc_map.get(doc_id)
            if doc is not None:
                similarity = 1.0 - dist
                output.append((doc, similarity))

        return output

    def count(self) -> int:
        return self._collection.count()


class PgVectorStore(VectorStore):
    """Vector store backed by PostgreSQL with pgvector extension.

    Requires: ``pip install pgvector sqlalchemy psycopg2-binary``
    """

    def __init__(
        self,
        connection_string: str,
        table_name: str = "warlock_control_embeddings",
        dimensions: int = 1536,
    ) -> None:
        from sqlalchemy import (
            Column,
            Float,
            MetaData,
            String,
            Table,
            Text,
            create_engine,
        )
        from pgvector.sqlalchemy import Vector

        self._engine = create_engine(connection_string)
        self._metadata = MetaData()
        self._dimensions = dimensions

        self._table = Table(
            table_name,
            self._metadata,
            Column("id", String(255), primary_key=True),
            Column("framework", String(100), nullable=False),
            Column("control_id", String(100), nullable=False),
            Column("family", String(100), nullable=False, server_default=""),
            Column("title", String(500), nullable=False, server_default=""),
            Column("description", Text, nullable=False, server_default=""),
            Column("text", Text, nullable=False),
            Column("embedding", Vector(dimensions)),
        )

        # Ensure pgvector extension and table exist
        with self._engine.connect() as conn:
            conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
            conn.commit()
        self._metadata.create_all(self._engine)

        # Local doc cache
        self._doc_cache: dict[str, ControlDocument] = {}

    def add(self, docs: list[ControlDocument]) -> None:
        if not docs:
            return

        from sqlalchemy import text

        rows = []
        for doc in docs:
            if doc.embedding is None:
                raise ValueError(
                    f"ControlDocument {doc.control_id} has no embedding."
                )
            doc_id = f"{doc.framework}:{doc.control_id}"
            rows.append({
                "id": doc_id,
                "framework": doc.framework,
                "control_id": doc.control_id,
                "family": doc.family,
                "title": doc.title,
                "description": doc.description,
                "text": doc.text,
                "embedding": doc.embedding,
            })
            self._doc_cache[doc_id] = doc

        # Upsert via INSERT ... ON CONFLICT
        with self._engine.connect() as conn:
            for row in rows:
                emb_str = "[" + ",".join(str(v) for v in row["embedding"]) + "]"
                conn.execute(
                    text(f"""
                        INSERT INTO {self._table.name}
                            (id, framework, control_id, family, title, description, text, embedding)
                        VALUES
                            (:id, :framework, :control_id, :family, :title, :description, :text, :embedding)
                        ON CONFLICT (id) DO UPDATE SET
                            text = EXCLUDED.text,
                            embedding = EXCLUDED.embedding
                    """),
                    {**row, "embedding": emb_str},
                )
            conn.commit()

    def search(
        self, query_embedding: list[float], top_k: int = 5,
    ) -> list[tuple[ControlDocument, float]]:
        from sqlalchemy import text

        emb_str = "[" + ",".join(str(v) for v in query_embedding) + "]"

        with self._engine.connect() as conn:
            result = conn.execute(
                text(f"""
                    SELECT id, framework, control_id, family, title, description, text,
                           1 - (embedding <=> :embedding::vector) AS similarity
                    FROM {self._table.name}
                    ORDER BY embedding <=> :embedding::vector
                    LIMIT :top_k
                """),
                {"embedding": emb_str, "top_k": top_k},
            )

            output: list[tuple[ControlDocument, float]] = []
            for row in result:
                doc = self._doc_cache.get(row.id)
                if doc is None:
                    doc = ControlDocument(
                        control_id=row.control_id,
                        framework=row.framework,
                        family=row.family,
                        title=row.title,
                        description=row.description,
                        text=row.text,
                    )
                    self._doc_cache[row.id] = doc
                output.append((doc, float(row.similarity)))

            return output

    def count(self) -> int:
        from sqlalchemy import text

        with self._engine.connect() as conn:
            result = conn.execute(
                text(f"SELECT COUNT(*) FROM {self._table.name}")
            )
            return result.scalar() or 0


# ---------------------------------------------------------------------------
# RAGControlMatcher — the main interface
# ---------------------------------------------------------------------------

def _build_control_text(
    framework_id: str,
    family_id: str,
    control_id: str,
    control_config: dict[str, Any],
) -> str:
    """Build a combined text representation of a control for embedding.

    Pulls from explicit title/description fields if present, otherwise
    constructs text from the control ID, family, check IDs, event types,
    and resource types.
    """
    parts: list[str] = []

    # Framework and structural info
    parts.append(f"Framework: {framework_id}")
    parts.append(f"Control family: {family_id}")
    parts.append(f"Control: {control_id}")

    # Title and description if available
    title = control_config.get("title", "")
    if title:
        parts.append(f"Title: {title}")
    description = control_config.get("description", "")
    if description:
        parts.append(f"Description: {description}")

    # Extract semantic info from checks
    check_context: list[str] = []
    for check in control_config.get("checks", []):
        check_id = check.get("id", "")
        if check_id:
            # Convert check IDs like "ac2_iam_users" to readable terms
            readable = check_id.replace("_", " ")
            check_context.append(readable)

        for et in check.get("event_types", []):
            check_context.append(et.replace("_", " "))

        for rt in check.get("resource_types", []):
            check_context.append(rt.replace("_", " "))

    if check_context:
        # Deduplicate while preserving order
        seen: set[str] = set()
        unique: list[str] = []
        for item in check_context:
            if item not in seen:
                seen.add(item)
                unique.append(item)
        parts.append("Related concepts: " + ", ".join(unique))

    return "\n".join(parts)


class RAGControlMatcher:
    """Semantic control matcher using vector embeddings.

    Indexes compliance control descriptions into a vector store and
    retrieves the most relevant controls for a given finding based on
    cosine similarity of their embeddings.
    """

    def __init__(self, embedder: EmbeddingProvider, store: VectorStore) -> None:
        self._embedder = embedder
        self._store = store

    @property
    def embedder(self) -> EmbeddingProvider:
        return self._embedder

    @property
    def store(self) -> VectorStore:
        return self._store

    def index_frameworks(self, framework_configs: dict[str, dict]) -> int:
        """Index all controls from framework YAML configs.

        Args:
            framework_configs: Mapping of framework_id to parsed YAML config.
                Each config should have a ``control_families`` key.

        Returns:
            Number of documents indexed.
        """
        docs: list[ControlDocument] = []
        texts: list[str] = []

        for framework_id, config in framework_configs.items():
            families = config.get("control_families", {})
            for family_id, family in families.items():
                controls = family.get("controls", {})
                for control_id, control_config in controls.items():
                    text = _build_control_text(
                        framework_id, family_id, control_id, control_config,
                    )
                    title = control_config.get("title", control_id)
                    description = control_config.get("description", "")

                    doc = ControlDocument(
                        control_id=control_id,
                        framework=framework_id,
                        family=family_id,
                        title=title,
                        description=description,
                        text=text,
                    )
                    docs.append(doc)
                    texts.append(text)

        if not docs:
            log.warning("No controls found in framework configs to index")
            return 0

        # For TF-IDF LocalEmbedder, fit the vocabulary on all control texts first
        if isinstance(self._embedder, LocalEmbedder) and self._embedder.is_tfidf:
            self._embedder.fit_tfidf(texts)

        log.info("Embedding %d control documents...", len(docs))
        embeddings = self._embedder.embed(texts)

        for doc, emb in zip(docs, embeddings):
            doc.embedding = emb

        self._store.add(docs)
        log.info("Indexed %d control documents into vector store", len(docs))
        return len(docs)

    def match(
        self,
        finding_title: str,
        finding_detail: dict[str, Any],
        top_k: int = 5,
        min_score: float = 0.6,
    ) -> list[tuple[str, str, float]]:
        """Find the most semantically similar controls for a finding.

        Args:
            finding_title: The finding's title/summary.
            finding_detail: The finding's detail dict (additional context).
            top_k: Maximum number of matches to return.
            min_score: Minimum cosine similarity threshold.

        Returns:
            List of (framework, control_id, similarity_score) tuples,
            sorted by descending similarity.
        """
        if self._store.count() == 0:
            log.warning("RAG store is empty — call index_frameworks() first")
            return []

        # Build query text from finding
        query_parts = [finding_title]

        # Extract useful fields from detail
        for key in ("description", "detail", "message", "reason", "check_id"):
            val = finding_detail.get(key)
            if val and isinstance(val, str):
                query_parts.append(val)

        # Include resource type if present
        resource_type = finding_detail.get("resource_type", "")
        if resource_type:
            query_parts.append(f"resource type: {resource_type}")

        query_text = " ".join(query_parts)
        query_embedding = self._embedder.embed_one(query_text)

        results = self._store.search(query_embedding, top_k=top_k)

        matches: list[tuple[str, str, float]] = []
        for doc, score in results:
            if score >= min_score:
                matches.append((doc.framework, doc.control_id, score))

        return matches

    def match_finding(
        self,
        finding: FindingData,
        top_k: int = 5,
        min_score: float = 0.6,
    ) -> list[ControlMappingData]:
        """Convenience method: match a FindingData to ControlMappingData objects.

        Builds the query from the finding's title, detail, and resource
        metadata, then returns ControlMappingData objects with
        ``mapping_method="semantic"``.
        """
        # Enrich detail with resource metadata for better matching
        enriched_detail = dict(finding.detail)
        if finding.resource_type:
            enriched_detail.setdefault("resource_type", finding.resource_type)
        if finding.observation_type:
            enriched_detail.setdefault("observation_type", finding.observation_type)

        raw_matches = self.match(
            finding_title=finding.title,
            finding_detail=enriched_detail,
            top_k=top_k,
            min_score=min_score,
        )

        mappings: list[ControlMappingData] = []
        for framework, control_id, score in raw_matches:
            mappings.append(ControlMappingData(
                finding_id=finding.id,
                framework=framework,
                control_id=control_id,
                mapping_method="semantic",
                confidence=round(score, 4),
            ))

        return mappings


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def create_rag_matcher(
    store: VectorStore | None = None,
) -> RAGControlMatcher:
    """Create a RAGControlMatcher using Warlock settings.

    Reads ``WLK_AI_PROVIDER`` and ``WLK_AI_API_KEY`` to choose the
    embedding provider:
      - If ai_provider is "openai" and ai_api_key is set -> OpenAIEmbedder
      - Otherwise -> LocalEmbedder (TF-IDF fallback)

    The store defaults to InMemoryStore if none is provided.
    """
    from warlock.config import get_settings

    settings = get_settings()

    # Pick embedder
    if settings.ai_provider == "openai" and settings.ai_api_key:
        embedder: EmbeddingProvider = OpenAIEmbedder(
            api_key=settings.ai_api_key,
            base_url=settings.ai_base_url or "https://api.openai.com/v1",
        )
        log.info("RAG embedder: OpenAI (text-embedding-3-small)")
    else:
        embedder = LocalEmbedder()
        if isinstance(embedder, LocalEmbedder) and embedder.is_tfidf:
            log.info("RAG embedder: TF-IDF fallback (no API key configured)")
        else:
            log.info("RAG embedder: sentence-transformers (local)")

    # Pick store
    if store is None:
        store = InMemoryStore()
        log.info("RAG store: InMemoryStore")

    return RAGControlMatcher(embedder=embedder, store=store)
