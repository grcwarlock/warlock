"""Google Gemini provider adapter.

Mirrors the URL construction and header patterns from
``warlock.assessors.ai_reasoning.GeminiReasoner`` but exposes the clean
``BaseProvider`` interface and adds:

- httpx sync and async HTTP
- 30 s timeout with 2-attempt exponential back-off
- Token-count extraction (``usageMetadata``)
- ``list_models`` filtered to models that support ``generateContent``
- API key always placed in the ``x-goog-api-key`` header — NEVER in the URL
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

_BASE = "https://generativelanguage.googleapis.com"
_GENERATE_PATH = "/v1beta/models/{model}:generateContent"
_MODELS_URL = f"{_BASE}/v1beta/models"

_FALLBACK_MODELS: list[ModelInfo] = [
    ModelInfo(id="gemini-2.0-flash", display_name="Gemini 2.0 Flash", verified=False),
    ModelInfo(id="gemini-2.0-flash-lite", display_name="Gemini 2.0 Flash Lite", verified=False),
    ModelInfo(id="gemini-1.5-pro", display_name="Gemini 1.5 Pro", verified=False),
    ModelInfo(id="gemini-1.5-flash", display_name="Gemini 1.5 Flash", verified=False),
    ModelInfo(id="gemini-1.5-flash-8b", display_name="Gemini 1.5 Flash 8B", verified=False),
]


class GeminiProvider(BaseProvider):
    """Google Gemini provider using the generateContent REST API."""

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

    def _generate_url(self) -> str:
        return _BASE + _GENERATE_PATH.format(model=self.model)

    def _headers(self) -> dict[str, str]:
        # API key goes in the header per CLAUDE.md security rule — never in the URL.
        return {"x-goog-api-key": self.api_key}

    def _payload(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float,
        max_tokens: int,
    ) -> dict:
        return {
            "system_instruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"parts": [{"text": user_prompt}]}],
            "generationConfig": {
                "maxOutputTokens": max_tokens,
                "temperature": temperature,
            },
        }

    @staticmethod
    def _parse_body(body: dict, model: str, latency_ms: int) -> ProviderResponse:
        text = body["candidates"][0]["content"]["parts"][0]["text"]
        usage = body.get("usageMetadata", {})
        return ProviderResponse(
            text=text,
            model=model,
            input_tokens=usage.get("promptTokenCount"),
            output_tokens=usage.get("candidatesTokenCount"),
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
        """Send a synchronous generateContent request to Gemini.

        Retries on 5xx errors and network failures with exponential back-off.
        """
        url = self._generate_url()
        headers = self._headers()
        payload = self._payload(system_prompt, user_prompt, temperature, max_tokens)
        last_exc: Exception | None = None

        for attempt in range(self.max_retries + 1):
            if attempt:
                backoff = self._backoff_seconds(attempt - 1)
                log.warning(
                    "Gemini complete attempt %d/%d — sleeping %.1fs: %s",
                    attempt + 1,
                    self.max_retries + 1,
                    backoff,
                    last_exc,
                )
                time.sleep(backoff)

            t0 = self._now_ms()
            try:
                resp = httpx.post(
                    url, headers=headers, json=payload, timeout=self.timeout
                )
                resp.raise_for_status()
                latency = self._now_ms() - t0
                return self._parse_body(resp.json(), self.model, latency)
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code < 500:
                    log.error("Gemini client error %s", exc.response.status_code)
                    raise
                last_exc = exc
            except Exception as exc:
                last_exc = exc

        log.exception("Gemini complete failed after %d attempts", self.max_retries + 1)
        raise RuntimeError(
            f"Gemini complete failed after {self.max_retries + 1} attempts"
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
        """Send an async generateContent request to Gemini.

        Uses ``httpx.AsyncClient``.  Retries with exponential back-off.
        """
        import asyncio

        url = self._generate_url()
        headers = self._headers()
        payload = self._payload(system_prompt, user_prompt, temperature, max_tokens)
        last_exc: Exception | None = None

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for attempt in range(self.max_retries + 1):
                if attempt:
                    backoff = self._backoff_seconds(attempt - 1)
                    log.warning(
                        "Gemini async attempt %d/%d — sleeping %.1fs: %s",
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
            f"Gemini complete_async failed after {self.max_retries + 1} attempts"
        ) from last_exc

    # ------------------------------------------------------------------
    # Model discovery
    # ------------------------------------------------------------------

    def list_models(self) -> list[ModelInfo]:
        """Return Gemini models that support ``generateContent``.

        Calls ``GET /v1beta/models`` with the ``x-goog-api-key`` header and
        filters to models whose ``supportedGenerationMethods`` includes
        ``generateContent``.

        Raises:
            httpx.HTTPError: On network or HTTP-level failure.
            Exception: On any other error (e.g. malformed response).

        Note:
            Callers (e.g. ``ModelDiscovery``) are responsible for catching
            exceptions and returning an appropriate fallback list.
        """
        resp = httpx.get(
            _MODELS_URL,
            headers={"x-goog-api-key": self.api_key},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        models: list[ModelInfo] = []
        for item in data.get("models", []):
            methods = item.get("supportedGenerationMethods", [])
            if "generateContent" not in methods:
                continue
            # The API returns names like "models/gemini-1.5-pro"; strip prefix.
            raw_name = item.get("name", "")
            model_id = raw_name.split("/")[-1] if "/" in raw_name else raw_name
            if model_id:
                models.append(
                    ModelInfo(
                        id=model_id,
                        display_name=item.get("displayName", model_id),
                        verified=True,
                    )
                )
        return models
