"""RAG-based semantic control matching.

Provides semantic search over control descriptions and remediation KB
entries to find relevant controls when explicit/resource rules miss.
Integrates with ControlMapper as a fallback mapping method.
"""

from __future__ import annotations

import json
import logging
import threading
from typing import Any, Callable

from warlock.ai.embeddings import EmbeddingProvider, cosine_similarity
from warlock.mappers.control_mapper import ControlMappingData
from warlock.normalizers.base import FindingData

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Vector Store — index and search embeddings via the database
# ---------------------------------------------------------------------------


class VectorStore:
    """Manages embedding storage and semantic search over the Embedding table.

    Thread-safe: uses a lock around DB writes.  Reads are safe for
    concurrent access since each call creates its own session.

    Parameters
    ----------
    session_factory:
        A callable that returns a new SQLAlchemy session (e.g.,
        ``sessionmaker(bind=engine)`` or a scoped_session).
    embedding_provider:
        The configured EmbeddingProvider for generating vectors.
    """

    def __init__(
        self,
        session_factory: Callable[[], Any],
        embedding_provider: EmbeddingProvider,
    ) -> None:
        self._session_factory = session_factory
        self._provider = embedding_provider
        self._write_lock = threading.Lock()

    # -- Indexing -------------------------------------------------------------

    def index_controls(self, controls: list[dict[str, Any]]) -> int:
        """Embed and store control descriptions.

        Each control dict should have: framework, control_id, control_name,
        control_description, and optionally control_family.

        Returns the number of controls indexed.
        """
        from warlock.db.models import Embedding

        texts: list[str] = []
        entity_ids: list[str] = []
        for ctrl in controls:
            framework = ctrl.get("framework", "")
            control_id = ctrl.get("control_id", "")
            control_name = ctrl.get("control_name", "")
            control_description = ctrl.get("control_description", "")

            text = f"{framework} {control_id}: {control_name}. {control_description}"
            entity_id = f"{framework}:{control_id}"

            texts.append(text)
            entity_ids.append(entity_id)

        if not texts:
            return 0

        # Generate embeddings in batch
        try:
            vectors = self._provider.embed_batch(texts)
        except Exception:
            log.exception("Failed to generate embeddings for controls")
            return 0

        # Store in database
        indexed = 0
        with self._write_lock:
            session = self._session_factory()
            try:
                for i, (text, entity_id, vector) in enumerate(zip(texts, entity_ids, vectors)):
                    # Upsert: delete existing then insert
                    existing = (
                        session.query(Embedding)
                        .filter_by(entity_type="control", entity_id=entity_id)
                        .first()
                    )
                    if existing:
                        session.delete(existing)
                        session.flush()

                    embedding = Embedding(
                        entity_type="control",
                        entity_id=entity_id,
                        entity_text=text,
                        vector=vector,
                        model_name=self._provider.model,
                        dimensions=len(vector),
                    )
                    session.add(embedding)
                    indexed += 1

                session.commit()
                log.info("Indexed %d control embeddings", indexed)
            except Exception:
                session.rollback()
                log.exception("Failed to store control embeddings")
                indexed = 0
            finally:
                session.close()

        return indexed

    def index_remediation_kb(self, kb_entries: list[dict[str, Any]]) -> int:
        """Embed and store remediation knowledge base entries.

        Each entry dict should have: key, title, description.

        Returns the number of entries indexed.
        """
        from warlock.db.models import Embedding

        texts: list[str] = []
        entity_ids: list[str] = []
        for entry in kb_entries:
            key = entry.get("key", "")
            title = entry.get("title", "")
            description = entry.get("description", "")

            text = f"{title}. {description}"
            entity_id = key

            texts.append(text)
            entity_ids.append(entity_id)

        if not texts:
            return 0

        try:
            vectors = self._provider.embed_batch(texts)
        except Exception:
            log.exception("Failed to generate embeddings for remediation KB")
            return 0

        indexed = 0
        with self._write_lock:
            session = self._session_factory()
            try:
                for text, entity_id, vector in zip(texts, entity_ids, vectors):
                    existing = (
                        session.query(Embedding)
                        .filter_by(entity_type="remediation", entity_id=entity_id)
                        .first()
                    )
                    if existing:
                        session.delete(existing)
                        session.flush()

                    embedding = Embedding(
                        entity_type="remediation",
                        entity_id=entity_id,
                        entity_text=text,
                        vector=vector,
                        model_name=self._provider.model,
                        dimensions=len(vector),
                    )
                    session.add(embedding)
                    indexed += 1

                session.commit()
                log.info("Indexed %d remediation KB embeddings", indexed)
            except Exception:
                session.rollback()
                log.exception("Failed to store remediation KB embeddings")
                indexed = 0
            finally:
                session.close()

        return indexed

    # -- Search ---------------------------------------------------------------

    def search_controls(
        self,
        query: str,
        top_k: int = 5,
        min_similarity: float = 0.6,
    ) -> list[dict[str, Any]]:
        """Search for controls semantically similar to the query.

        Embeds the query text, loads all control embeddings from the DB,
        computes cosine similarity against each, and returns the top_k
        results above the min_similarity threshold.

        Parameters
        ----------
        query:
            The text to search for (e.g., finding title + description).
        top_k:
            Maximum number of results to return.
        min_similarity:
            Minimum cosine similarity score (0.0 to 1.0) to include.

        Returns
        -------
        List of dicts, each with: framework, control_id, similarity, entity_text.
        Sorted by similarity descending.
        """
        from warlock.db.models import Embedding

        try:
            query_vector = self._provider.embed(query)
        except Exception:
            log.exception("Failed to embed query for control search")
            return []

        session = self._session_factory()
        try:
            embeddings = (
                session.query(Embedding)
                .filter_by(entity_type="control")
                .all()
            )

            results: list[dict[str, Any]] = []
            for emb in embeddings:
                stored_vector = emb.vector
                if not stored_vector:
                    continue

                sim = cosine_similarity(query_vector, stored_vector)
                if sim >= min_similarity:
                    # Parse entity_id: "framework:control_id"
                    parts = emb.entity_id.split(":", 1)
                    framework = parts[0] if len(parts) > 1 else ""
                    control_id = parts[1] if len(parts) > 1 else emb.entity_id

                    results.append({
                        "framework": framework,
                        "control_id": control_id,
                        "similarity": round(sim, 4),
                        "entity_text": emb.entity_text,
                    })

            # Sort by similarity descending and return top_k
            results.sort(key=lambda r: r["similarity"], reverse=True)
            return results[:top_k]
        except Exception:
            log.exception("Failed to search control embeddings")
            return []
        finally:
            session.close()

    def search_similar_findings(
        self,
        finding_text: str,
        top_k: int = 5,
        min_similarity: float = 0.6,
    ) -> list[dict[str, Any]]:
        """Search for findings semantically similar to the given text.

        Parameters
        ----------
        finding_text:
            Text description of the finding to match.
        top_k:
            Maximum number of results.
        min_similarity:
            Minimum cosine similarity threshold.

        Returns
        -------
        List of dicts with: entity_id, similarity, entity_text.
        """
        from warlock.db.models import Embedding

        try:
            query_vector = self._provider.embed(finding_text)
        except Exception:
            log.exception("Failed to embed query for finding search")
            return []

        session = self._session_factory()
        try:
            embeddings = (
                session.query(Embedding)
                .filter_by(entity_type="finding")
                .all()
            )

            results: list[dict[str, Any]] = []
            for emb in embeddings:
                stored_vector = emb.vector
                if not stored_vector:
                    continue

                sim = cosine_similarity(query_vector, stored_vector)
                if sim >= min_similarity:
                    results.append({
                        "entity_id": emb.entity_id,
                        "similarity": round(sim, 4),
                        "entity_text": emb.entity_text,
                    })

            results.sort(key=lambda r: r["similarity"], reverse=True)
            return results[:top_k]
        except Exception:
            log.exception("Failed to search finding embeddings")
            return []
        finally:
            session.close()


# ---------------------------------------------------------------------------
# Semantic Mapper — integrates with ControlMapper as a fallback
# ---------------------------------------------------------------------------


class SemanticMapper:
    """Maps findings to controls using semantic similarity.

    This is a FALLBACK mapper -- only invoked when explicit and resource
    rules in ControlMapper produce no mappings.

    Parameters
    ----------
    vector_store:
        The VectorStore instance for semantic search.
    min_similarity:
        Minimum cosine similarity to accept a mapping.
    """

    def __init__(
        self,
        vector_store: VectorStore,
        min_similarity: float = 0.6,
    ) -> None:
        self._vector_store = vector_store
        self._min_similarity = min_similarity

    def map_finding(self, finding: FindingData) -> list[ControlMappingData]:
        """Attempt semantic control mapping for a finding.

        Builds a query string from the finding's title and detail, then
        searches the vector store for similar controls.

        Returns
        -------
        List of ControlMappingData with mapping_method="semantic" and
        confidence set to the cosine similarity score.
        """
        # Build a query string from the finding
        detail_str = ""
        if finding.detail:
            try:
                detail_str = json.dumps(finding.detail, default=str)
            except (TypeError, ValueError):
                detail_str = str(finding.detail)

        query = f"{finding.title}. {finding.observation_type}: {detail_str}"

        # Truncate overly long queries to avoid embedding API limits
        if len(query) > 2000:
            query = query[:2000]

        results = self._vector_store.search_controls(
            query=query,
            top_k=5,
            min_similarity=self._min_similarity,
        )

        mappings: list[ControlMappingData] = []
        for result in results:
            mappings.append(
                ControlMappingData(
                    finding_id=finding.id,
                    framework=result["framework"],
                    control_id=result["control_id"],
                    mapping_method="semantic",
                    confidence=result["similarity"],
                )
            )

        if mappings:
            log.debug(
                "Semantic mapper found %d controls for finding %s (top: %s:%s @ %.3f)",
                len(mappings),
                finding.id[:8],
                mappings[0].framework,
                mappings[0].control_id,
                mappings[0].confidence,
            )

        return mappings
