"""Ollama provider adapter.

Mirrors the URL construction and header patterns from
``warlock.assessors.ai_reasoning.OllamaReasoner``.  Ollama exposes an
OpenAI-compatible ``/v1/chat/completions`` endpoint, so request/response
shapes are identical to ``OpenAIProvider``.

Differences from the OpenAI provider:
- Default base URL is ``http://localhost:11434`` (local inference server)
- ``Authorization: Bearer`` header is only added when ``api_key`` is non-empty
- ``list_models`` calls ``GET <base_url>/api/tags`` (Ollama's native endpoint)
"""

from __future__ import annotations

import logging
import time

import httpx

from warlock.ai.providers.base import (
    DEFAULT_MAX_RETRIES,
    DEFAULT_TIMEOUT,
    BaseProvider,
    ProviderResponse,
)
from warlock.ai.types import ModelInfo

log = logging.getLogger(__name__)

_DEFAULT_BASE = "http://localhost:11434"
_CHAT_PATH = "/v1/chat/completions"
_TAGS_PATH = "/api/tags"

_FALLBACK_MODELS: list[ModelInfo] = [
    ModelInfo(id="llama3.3", display_name="Llama 3.3", verified=False),
    ModelInfo(id="llama3.2", display_name="Llama 3.2", verified=False),
    ModelInfo(id="mistral", display_name="Mistral", verified=False),
    ModelInfo(id="deepseek-r1", display_name="DeepSeek R1", verified=False),
    ModelInfo(id="qwen2.5", display_name="Qwen 2.5", verified=False),
]


class OllamaProvider(BaseProvider):
    """Ollama local-inference provider using the OpenAI-compatible endpoint."""

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
        resolved = (base_url or _DEFAULT_BASE).rstrip("/")
        # Ollama Cloud redirects api.ollama.com → ollama.com and drops
        # the Authorization header on cross-origin redirect. Use the
        # final URL directly to avoid the redirect + auth loss.
        if resolved == "https://api.ollama.com":
            resolved = "https://ollama.com"
        self._base = resolved

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _payload(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float,
        max_tokens: int,
    ) -> dict:
        payload: dict = {
            "model": self.model,
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        # Ollama accepts max_tokens only for certain model families; always
        # include it — the server will ignore it if unsupported.
        if max_tokens:
            payload["max_tokens"] = max_tokens
        return payload

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
        """Send a synchronous chat completion request to Ollama.

        Retries on 5xx errors and network failures.  Because Ollama is a local
        service it rarely returns 5xx, but back-off is still applied for
        robustness when running behind a remote proxy.
        """
        url = self._base + _CHAT_PATH
        headers = self._headers()
        payload = self._payload(system_prompt, user_prompt, temperature, max_tokens)
        last_exc: Exception | None = None

        for attempt in range(self.max_retries + 1):
            if attempt:
                backoff = self._backoff_seconds(attempt - 1)
                log.warning(
                    "Ollama complete attempt %d/%d — sleeping %.1fs: %s",
                    attempt + 1,
                    self.max_retries + 1,
                    backoff,
                    last_exc,
                )
                time.sleep(backoff)

            t0 = self._now_ms()
            try:
                resp = httpx.post(
                    url,
                    headers=headers,
                    json=payload,
                    timeout=self.timeout,
                    follow_redirects=True,
                )
                resp.raise_for_status()
                latency = self._now_ms() - t0
                return self._parse_body(resp.json(), self.model, latency)
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code < 500:
                    log.error("Ollama client error %s", exc.response.status_code)
                    raise
                last_exc = exc
            except Exception as exc:
                last_exc = exc

        log.exception("Ollama complete failed after %d attempts", self.max_retries + 1)
        raise RuntimeError(
            f"Ollama complete failed after {self.max_retries + 1} attempts"
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
        """Send an async chat completion request to Ollama.

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
                        "Ollama async attempt %d/%d — sleeping %.1fs: %s",
                        attempt + 1,
                        self.max_retries + 1,
                        backoff,
                        last_exc,
                    )
                    await asyncio.sleep(backoff)

                t0 = self._now_ms()
                try:
                    resp = await client.post(
                        url, headers=headers, json=payload, follow_redirects=True
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
            f"Ollama complete_async failed after {self.max_retries + 1} attempts"
        ) from last_exc

    # ------------------------------------------------------------------
    # Model discovery
    # ------------------------------------------------------------------

    def list_models(self) -> list[ModelInfo]:
        """Return models available in the local Ollama instance.

        Calls ``GET <base_url>/api/tags``.  Adds an ``Authorization: Bearer``
        header only when ``api_key`` is non-empty.

        Raises:
            httpx.HTTPError: On network or HTTP-level failure (e.g. Ollama not
                running).
            Exception: On any other error (e.g. malformed response).

        Note:
            Callers (e.g. ``ModelDiscovery``) are responsible for catching
            exceptions and returning an appropriate fallback list.
        """
        url = self._base + _TAGS_PATH
        headers: dict[str, str] = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        resp = httpx.get(url, headers=headers, timeout=self.timeout, follow_redirects=True)
        resp.raise_for_status()
        data = resp.json()
        models: list[ModelInfo] = []
        for item in data.get("models", []):
            model_id = item.get("name", "")
            if model_id:
                models.append(
                    ModelInfo(
                        id=model_id,
                        display_name=model_id,
                        verified=True,
                    )
                )
        return models
