"""Embedding generation via AI providers.

Uses the same provider infrastructure (httpx, no SDK deps) to generate
embeddings from OpenAI-compatible endpoints or Ollama.
"""

from __future__ import annotations

import logging
import math
from typing import Any

import httpx

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default models per provider
# ---------------------------------------------------------------------------

_DEFAULT_MODELS: dict[str, str] = {
    "openai": "text-embedding-3-small",
    "ollama": "nomic-embed-text",
}

_DEFAULT_DIMENSIONS: dict[str, int] = {
    "text-embedding-3-small": 1536,
    "text-embedding-3-large": 3072,
    "nomic-embed-text": 768,
}

_DEFAULT_BASE_URLS: dict[str, str] = {
    "openai": "https://api.openai.com",
    "ollama": "http://localhost:11434",
}


# ---------------------------------------------------------------------------
# Pure-Python cosine similarity
# ---------------------------------------------------------------------------


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Compute cosine similarity between two vectors.

    Returns a value in [-1.0, 1.0]. Returns 0.0 if either vector has
    zero magnitude to avoid division by zero.
    """
    if len(a) != len(b):
        raise ValueError(f"Vector dimension mismatch: {len(a)} vs {len(b)}")

    dot = 0.0
    norm_a = 0.0
    norm_b = 0.0
    for ai, bi in zip(a, b):
        dot += ai * bi
        norm_a += ai * ai
        norm_b += bi * bi

    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0

    return dot / (math.sqrt(norm_a) * math.sqrt(norm_b))


# ---------------------------------------------------------------------------
# Embedding Provider
# ---------------------------------------------------------------------------


class EmbeddingProvider:
    """Generate embeddings via OpenAI-compatible or Ollama endpoints.

    Uses httpx directly — no SDK dependencies.  Supports:
    - OpenAI (and any OpenAI-compatible endpoint like vLLM, LiteLLM)
    - Ollama (local models)

    Parameters
    ----------
    provider:
        Provider name: "openai" or "ollama".
    api_key:
        API key for authentication.  Not required for Ollama.
    model:
        Embedding model name.  Defaults per provider if empty.
    base_url:
        Base URL for the API.  Defaults per provider if empty.
    """

    def __init__(
        self,
        provider: str,
        api_key: str = "",
        model: str = "",
        base_url: str = "",
    ) -> None:
        self.provider = provider.lower()
        self.api_key = api_key
        self.model = model or _DEFAULT_MODELS.get(self.provider, "text-embedding-3-small")
        self.base_url = (
            base_url.rstrip("/")
            if base_url
            else _DEFAULT_BASE_URLS.get(self.provider, "https://api.openai.com")
        )
        self._dimensions: int | None = _DEFAULT_DIMENSIONS.get(self.model)

    @property
    def dimensions(self) -> int:
        """Return the embedding dimensionality for the configured model.

        Returns the known dimension if available, otherwise a sensible
        default.  The actual dimension is confirmed on first embed call.
        """
        return self._dimensions or 1536

    def embed(self, text: str) -> list[float]:
        """Generate an embedding vector for a single text string.

        Returns a list of floats representing the embedding vector.
        """
        if self.provider == "ollama":
            return self._embed_ollama(text)
        return self._embed_openai(text)

    def embed_batch(self, texts: list[str], batch_size: int = 100) -> list[list[float]]:
        """Generate embeddings for multiple texts.

        For OpenAI-compatible providers, sends texts in batches (the API
        accepts multiple inputs per request).  For Ollama, sends one at
        a time since the /api/embed endpoint handles batching internally.

        Parameters
        ----------
        texts:
            List of text strings to embed.
        batch_size:
            Maximum number of texts per API call (OpenAI-compatible only).

        Returns
        -------
        List of embedding vectors in the same order as input texts.
        """
        if not texts:
            return []

        if self.provider == "ollama":
            return self._embed_batch_ollama(texts)
        return self._embed_batch_openai(texts, batch_size)

    # -- OpenAI-compatible embedding -----------------------------------------

    def _embed_openai(self, text: str) -> list[float]:
        """Single embedding via OpenAI /v1/embeddings endpoint."""
        url = f"{self.base_url}/v1/embeddings"
        headers = self._openai_headers()
        payload: dict[str, Any] = {
            "input": text,
            "model": self.model,
        }

        resp = httpx.post(url, json=payload, headers=headers, timeout=30.0)
        resp.raise_for_status()
        body = resp.json()

        vector = body["data"][0]["embedding"]
        self._dimensions = len(vector)
        return vector

    def _embed_batch_openai(self, texts: list[str], batch_size: int) -> list[list[float]]:
        """Batch embedding via OpenAI /v1/embeddings endpoint."""
        url = f"{self.base_url}/v1/embeddings"
        headers = self._openai_headers()
        all_vectors: list[list[float]] = []

        for i in range(0, len(texts), batch_size):
            batch = texts[i : i + batch_size]
            payload: dict[str, Any] = {
                "input": batch,
                "model": self.model,
            }

            resp = httpx.post(url, json=payload, headers=headers, timeout=60.0)
            resp.raise_for_status()
            body = resp.json()

            # OpenAI returns data sorted by index
            sorted_data = sorted(body["data"], key=lambda x: x["index"])
            batch_vectors = [item["embedding"] for item in sorted_data]

            if batch_vectors:
                self._dimensions = len(batch_vectors[0])

            all_vectors.extend(batch_vectors)

        return all_vectors

    def _openai_headers(self) -> dict[str, str]:
        """Build headers for OpenAI-compatible requests."""
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    # -- Ollama embedding ----------------------------------------------------

    def _embed_ollama(self, text: str) -> list[float]:
        """Single embedding via Ollama /api/embed endpoint."""
        url = f"{self.base_url}/api/embed"
        payload: dict[str, Any] = {
            "model": self.model,
            "input": text,
        }

        resp = httpx.post(
            url, json=payload, headers={"Content-Type": "application/json"}, timeout=30.0
        )
        resp.raise_for_status()
        body = resp.json()

        # Ollama returns {"embeddings": [[...]]} for single input
        vector = body["embeddings"][0]
        self._dimensions = len(vector)
        return vector

    def _embed_batch_ollama(self, texts: list[str]) -> list[list[float]]:
        """Batch embedding via Ollama /api/embed endpoint.

        Ollama's /api/embed accepts a list of inputs natively.
        """
        url = f"{self.base_url}/api/embed"
        payload: dict[str, Any] = {
            "model": self.model,
            "input": texts,
        }

        resp = httpx.post(
            url, json=payload, headers={"Content-Type": "application/json"}, timeout=120.0
        )
        resp.raise_for_status()
        body = resp.json()

        vectors = body["embeddings"]
        if vectors:
            self._dimensions = len(vectors[0])
        return vectors
