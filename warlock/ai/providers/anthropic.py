"""Anthropic provider adapter.

Mirrors the URL construction and header patterns from
``warlock.assessors.ai_reasoning.AnthropicReasoner`` but exposes the clean
``BaseProvider`` interface and adds:

- httpx sync and async HTTP
- 30 s timeout with 2-attempt exponential back-off
- Token-count extraction from the usage block
- ``list_models`` via the Anthropic models endpoint
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

_MESSAGES_URL = "https://api.anthropic.com/v1/messages"
_MODELS_URL = "https://api.anthropic.com/v1/models"
_ANTHROPIC_VERSION = "2023-06-01"

# Fallback model list returned when the API is unreachable.
_FALLBACK_MODELS: list[ModelInfo] = [
    ModelInfo(id="claude-opus-4-5", display_name="Claude Opus 4.5", verified=False),
    ModelInfo(id="claude-sonnet-4-5", display_name="Claude Sonnet 4.5", verified=False),
    ModelInfo(id="claude-haiku-3-5", display_name="Claude Haiku 3.5", verified=False),
    ModelInfo(id="claude-3-opus-20240229", display_name="Claude 3 Opus", verified=False),
    ModelInfo(id="claude-3-5-sonnet-20241022", display_name="Claude 3.5 Sonnet", verified=False),
    ModelInfo(id="claude-3-haiku-20240307", display_name="Claude 3 Haiku", verified=False),
]


class AnthropicProvider(BaseProvider):
    """Anthropic Claude provider using the Messages API."""

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

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {
            "x-api-key": self.api_key,
            "anthropic-version": _ANTHROPIC_VERSION,
            "content-type": "application/json",
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
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
        }

    @staticmethod
    def _parse_body(body: dict, model: str, latency_ms: int) -> ProviderResponse:
        text = body["content"][0]["text"]
        usage = body.get("usage", {})
        return ProviderResponse(
            text=text,
            model=model,
            input_tokens=usage.get("input_tokens"),
            output_tokens=usage.get("output_tokens"),
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
        """Send a synchronous completion request to Anthropic.

        Retries up to ``max_retries`` times with exponential back-off on
        transient errors (5xx, network failures).
        """
        headers = self._headers()
        payload = self._payload(system_prompt, user_prompt, temperature, max_tokens)
        last_exc: Exception | None = None

        for attempt in range(self.max_retries + 1):
            if attempt:
                backoff = self._backoff_seconds(attempt - 1)
                log.warning(
                    "Anthropic complete attempt %d/%d — sleeping %.1fs after error: %s",
                    attempt + 1,
                    self.max_retries + 1,
                    backoff,
                    last_exc,
                )
                time.sleep(backoff)

            t0 = self._now_ms()
            try:
                resp = httpx.post(
                    _MESSAGES_URL,
                    headers=headers,
                    json=payload,
                    timeout=self.timeout,
                )
                resp.raise_for_status()
                latency = self._now_ms() - t0
                return self._parse_body(resp.json(), self.model, latency)
            except httpx.HTTPStatusError as exc:
                # Do not retry client errors (4xx).
                if exc.response.status_code < 500:
                    log.error("Anthropic client error %s", exc.response.status_code)
                    raise
                last_exc = exc
            except Exception as exc:
                last_exc = exc

        log.exception("Anthropic complete failed after %d attempts", self.max_retries + 1)
        raise RuntimeError(
            f"Anthropic complete failed after {self.max_retries + 1} attempts"
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
        """Send an async completion request to Anthropic.

        Uses ``httpx.AsyncClient`` for non-blocking I/O.  Retries with
        exponential back-off on transient errors.
        """
        import asyncio

        headers = self._headers()
        payload = self._payload(system_prompt, user_prompt, temperature, max_tokens)
        last_exc: Exception | None = None

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for attempt in range(self.max_retries + 1):
                if attempt:
                    backoff = self._backoff_seconds(attempt - 1)
                    log.warning(
                        "Anthropic async attempt %d/%d — sleeping %.1fs: %s",
                        attempt + 1,
                        self.max_retries + 1,
                        backoff,
                        last_exc,
                    )
                    await asyncio.sleep(backoff)

                t0 = self._now_ms()
                try:
                    resp = await client.post(
                        _MESSAGES_URL, headers=headers, json=payload
                    )
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
            f"Anthropic complete_async failed after {self.max_retries + 1} attempts"
        ) from last_exc

    # ------------------------------------------------------------------
    # Model discovery
    # ------------------------------------------------------------------

    def list_models(self) -> list[ModelInfo]:
        """Return available Anthropic models.

        Calls ``GET /v1/models`` with the ``x-api-key`` header.

        Raises:
            httpx.HTTPError: On network or HTTP-level failure.
            Exception: On any other error (e.g. malformed response).

        Note:
            Callers (e.g. ``ModelDiscovery``) are responsible for catching
            exceptions and returning an appropriate fallback list.
        """
        resp = httpx.get(
            _MODELS_URL,
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": _ANTHROPIC_VERSION,
            },
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        models: list[ModelInfo] = []
        for item in data.get("data", []):
            model_id = item.get("id", "")
            if model_id:
                models.append(
                    ModelInfo(
                        id=model_id,
                        display_name=item.get("display_name", model_id),
                        verified=True,
                    )
                )
        return models
