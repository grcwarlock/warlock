"""OpenAI provider adapter.

Mirrors the URL construction and header patterns from
``warlock.assessors.ai_reasoning.OpenAIReasoner`` but exposes the clean
``BaseProvider`` interface and adds:

- httpx sync and async HTTP
- 30 s timeout with 2-attempt exponential back-off
- Token-count extraction from the usage block
- ``list_models`` filtered to ``owned_by in ("openai", "system")``
- Compatible with OpenAI-API-compatible base URLs (Azure, proxies, etc.)
"""

from __future__ import annotations

import logging
import time

import httpx

from warlock.ai.providers.base import (
    BaseProvider,
    DEFAULT_MAX_RETRIES,
    DEFAULT_TIMEOUT,
    ProviderResponse,
)
from warlock.ai.types import ModelInfo

log = logging.getLogger(__name__)

_DEFAULT_BASE = "https://api.openai.com"
_CHAT_PATH = "/v1/chat/completions"
_MODELS_PATH = "/v1/models"

# Owned-by values that represent first-party OpenAI models.
_OPENAI_OWNERS = frozenset({"openai", "system"})

_FALLBACK_MODELS: list[ModelInfo] = [
    ModelInfo(id="gpt-4o", display_name="GPT-4o", verified=False),
    ModelInfo(id="gpt-4o-mini", display_name="GPT-4o mini", verified=False),
    ModelInfo(id="gpt-4-turbo", display_name="GPT-4 Turbo", verified=False),
    ModelInfo(id="gpt-4", display_name="GPT-4", verified=False),
    ModelInfo(id="gpt-3.5-turbo", display_name="GPT-3.5 Turbo", verified=False),
    ModelInfo(id="o1", display_name="o1", verified=False),
    ModelInfo(id="o1-mini", display_name="o1-mini", verified=False),
]


class OpenAIProvider(BaseProvider):
    """OpenAI (or compatible) chat-completions provider."""

    def __init__(
        self,
        api_key: str,
        model: str,
        base_url: str = "",
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> None:
        super().__init__(
            api_key=api_key,
            model=model,
            base_url=base_url,
            timeout=timeout,
            max_retries=max_retries,
        )
        self._base = (base_url or _DEFAULT_BASE).rstrip("/")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def _payload(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float,
        max_tokens: int,
    ) -> dict:
        return {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }

    @staticmethod
    def _parse_body(body: dict, model: str, latency_ms: int) -> ProviderResponse:
        text = body["choices"][0]["message"]["content"]
        usage = body.get("usage", {})
        return ProviderResponse(
            text=text,
            model=model,
            input_tokens=usage.get("prompt_tokens"),
            output_tokens=usage.get("completion_tokens"),
            latency_ms=latency_ms,
        )

    # ------------------------------------------------------------------
    # Sync completion
    # ------------------------------------------------------------------

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ) -> ProviderResponse:
        """Send a synchronous chat completion request to OpenAI.

        Retries on 5xx errors and network failures with exponential back-off.
        4xx errors are raised immediately — they indicate a caller mistake.
        """
        url = self._base + _CHAT_PATH
        headers = self._headers()
        payload = self._payload(system_prompt, user_prompt, temperature, max_tokens)
        last_exc: Exception | None = None

        for attempt in range(self.max_retries + 1):
            if attempt:
                backoff = self._backoff_seconds(attempt - 1)
                log.warning(
                    "OpenAI complete attempt %d/%d — sleeping %.1fs: %s",
                    attempt + 1,
                    self.max_retries + 1,
                    backoff,
                    last_exc,
                )
                time.sleep(backoff)

            t0 = self._now_ms()
            try:
                resp = httpx.post(url, headers=headers, json=payload, timeout=self.timeout)
                resp.raise_for_status()
                latency = self._now_ms() - t0
                return self._parse_body(resp.json(), self.model, latency)
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code < 500:
                    log.error("OpenAI client error %s", exc.response.status_code)
                    raise
                last_exc = exc
            except Exception as exc:
                last_exc = exc

        log.exception("OpenAI complete failed after %d attempts", self.max_retries + 1)
        raise RuntimeError(
            f"OpenAI complete failed after {self.max_retries + 1} attempts"
        ) from last_exc

    # ------------------------------------------------------------------
    # Async completion
    # ------------------------------------------------------------------

    async def complete_async(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ) -> ProviderResponse:
        """Send an async chat completion request to OpenAI.

        Uses ``httpx.AsyncClient``.  Retries with exponential back-off.
        """
        import asyncio

        url = self._base + _CHAT_PATH
        headers = self._headers()
        payload = self._payload(system_prompt, user_prompt, temperature, max_tokens)
        last_exc: Exception | None = None

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for attempt in range(self.max_retries + 1):
                if attempt:
                    backoff = self._backoff_seconds(attempt - 1)
                    log.warning(
                        "OpenAI async attempt %d/%d — sleeping %.1fs: %s",
                        attempt + 1,
                        self.max_retries + 1,
                        backoff,
                        last_exc,
                    )
                    await asyncio.sleep(backoff)

                t0 = self._now_ms()
                try:
                    resp = await client.post(url, headers=headers, json=payload)
                    resp.raise_for_status()
                    latency = self._now_ms() - t0
                    return self._parse_body(resp.json(), self.model, latency)
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code < 500:
                        raise
                    last_exc = exc
                except Exception as exc:
                    last_exc = exc

        raise RuntimeError(
            f"OpenAI complete_async failed after {self.max_retries + 1} attempts"
        ) from last_exc

    # ------------------------------------------------------------------
    # Model discovery
    # ------------------------------------------------------------------

    def list_models(self) -> list[ModelInfo]:
        """Return first-party OpenAI models available on this API key.

        Calls ``GET /v1/models`` with a ``Bearer`` token and filters results
        to ``owned_by in ("openai", "system")``.

        Raises:
            httpx.HTTPError: On network or HTTP-level failure.
            Exception: On any other error (e.g. malformed response).

        Note:
            Callers (e.g. ``ModelDiscovery``) are responsible for catching
            exceptions and returning an appropriate fallback list.
        """
        url = self._base + _MODELS_PATH
        resp = httpx.get(
            url,
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        models: list[ModelInfo] = []
        for item in data.get("data", []):
            if item.get("owned_by", "") in _OPENAI_OWNERS:
                model_id = item.get("id", "")
                if model_id:
                    models.append(
                        ModelInfo(
                            id=model_id,
                            display_name=model_id,
                            verified=True,
                        )
                    )
        return models
