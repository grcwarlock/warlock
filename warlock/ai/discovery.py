"""Model discovery and validation for the Warlock AI layer.

``ModelDiscovery`` answers two questions:

1. What models are available for a given provider and API key?
2. Does this (provider, model, api_key) combination actually work right now?

Both operations are intentionally lightweight and fail-safe — discovery errors
return a ``DiscoveryResult`` with ``connected=False`` and an error string
rather than raising, so callers can surface the error gracefully without
crashing the wider pipeline.
"""

from __future__ import annotations

import logging

from warlock.ai.providers import create_provider
from warlock.ai.types import DiscoveryResult, ModelInfo

log = logging.getLogger(__name__)

# Prompt used to validate that a model is reachable and responding.
_VALIDATION_SYSTEM = "You are a connectivity test assistant."
_VALIDATION_USER = "Reply with only the word: ok"

# Per-provider hardcoded fallbacks used when the live API is unreachable.
_FALLBACK_MODELS: dict[str, list[ModelInfo]] = {
    "anthropic": [
        ModelInfo(id="claude-opus-4-5", display_name="Claude Opus 4.5", verified=False),
        ModelInfo(id="claude-sonnet-4-5", display_name="Claude Sonnet 4.5", verified=False),
        ModelInfo(id="claude-haiku-3-5", display_name="Claude Haiku 3.5", verified=False),
        ModelInfo(id="claude-3-opus-20240229", display_name="Claude 3 Opus", verified=False),
        ModelInfo(
            id="claude-3-5-sonnet-20241022", display_name="Claude 3.5 Sonnet", verified=False
        ),
        ModelInfo(id="claude-3-haiku-20240307", display_name="Claude 3 Haiku", verified=False),
    ],
    "openai": [
        ModelInfo(id="gpt-4o", display_name="GPT-4o", verified=False),
        ModelInfo(id="gpt-4o-mini", display_name="GPT-4o mini", verified=False),
        ModelInfo(id="gpt-4-turbo", display_name="GPT-4 Turbo", verified=False),
        ModelInfo(id="gpt-4", display_name="GPT-4", verified=False),
        ModelInfo(id="gpt-3.5-turbo", display_name="GPT-3.5 Turbo", verified=False),
        ModelInfo(id="o1", display_name="o1", verified=False),
        ModelInfo(id="o1-mini", display_name="o1-mini", verified=False),
    ],
    "gemini": [
        ModelInfo(id="gemini-2.0-flash", display_name="Gemini 2.0 Flash", verified=False),
        ModelInfo(id="gemini-2.0-flash-lite", display_name="Gemini 2.0 Flash Lite", verified=False),
        ModelInfo(id="gemini-1.5-pro", display_name="Gemini 1.5 Pro", verified=False),
        ModelInfo(id="gemini-1.5-flash", display_name="Gemini 1.5 Flash", verified=False),
        ModelInfo(id="gemini-1.5-flash-8b", display_name="Gemini 1.5 Flash 8B", verified=False),
    ],
    "ollama": [
        ModelInfo(id="llama3.3", display_name="Llama 3.3", verified=False),
        ModelInfo(id="llama3.2", display_name="Llama 3.2", verified=False),
        ModelInfo(id="mistral", display_name="Mistral", verified=False),
        ModelInfo(id="deepseek-r1", display_name="DeepSeek R1", verified=False),
        ModelInfo(id="qwen2.5", display_name="Qwen 2.5", verified=False),
    ],
}


class ModelDiscovery:
    """Discovers and validates AI models across providers.

    This class is stateless — every method creates a short-lived provider
    instance for the duration of the call.  No caching is performed here;
    callers that need caching should wrap this class.
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def discover(
        self,
        provider: str,
        api_key: str,
        base_url: str = "",
    ) -> DiscoveryResult:
        """List models available for a provider.

        Delegates to the provider's ``list_models()`` implementation.  If the
        provider raises or returns an empty list the method falls back to the
        hardcoded list for that provider and sets ``connected=False``.

        Args:
            provider: Provider name — ``"anthropic"``, ``"openai"``,
                ``"gemini"``, or ``"ollama"``.
            api_key: API key for the provider.
            base_url: Optional base URL override (useful for Ollama or proxies).

        Returns:
            ``DiscoveryResult`` with ``connected=True`` and the live model list
            on success, or ``connected=False`` with the fallback model list and
            an error message on failure.
        """
        # Use a sentinel model name — list_models does not call the inference
        # endpoint, so the model value is irrelevant here.
        _SENTINEL_MODEL = "_discovery_"

        try:
            p = create_provider(
                provider_name=provider,
                api_key=api_key,
                model=_SENTINEL_MODEL,
                base_url=base_url,
            )
        except ValueError as exc:
            log.warning("ModelDiscovery.discover: invalid provider %r — %s", provider, exc)
            return DiscoveryResult(
                connected=False,
                models=self._fallback(provider),
                error=str(exc),
            )

        try:
            models = p.list_models()
            if not models:
                log.warning(
                    "ModelDiscovery.discover: %r returned empty list — using fallback",
                    provider,
                )
                return DiscoveryResult(
                    connected=False,
                    models=self._fallback(provider),
                    error="Provider returned empty model list",
                )
            log.debug("ModelDiscovery.discover: %r returned %d models", provider, len(models))
            return DiscoveryResult(
                connected=True,
                models=models,
            )
        except Exception as exc:
            log.warning(
                "ModelDiscovery.discover: %r list_models raised — using fallback: %s",
                provider,
                exc,
            )
            return DiscoveryResult(
                connected=False,
                models=self._fallback(provider),
                error=str(exc),
            )

    def validate_model(
        self,
        provider: str,
        api_key: str,
        model: str,
        base_url: str = "",
    ) -> bool:
        """Verify that a specific model is reachable and returns a response.

        Sends a minimal test prompt and returns ``True`` if the provider
        returns any non-empty text.  Returns ``False`` on any error, including
        network failures, authentication errors, or empty responses.

        This method does NOT retry — a single round-trip is sufficient to
        confirm connectivity, and retries would add unwanted latency to the
        setup flow.

        Args:
            provider: Provider name.
            api_key: API key for the provider.
            model: Exact model identifier to test.
            base_url: Optional base URL override.

        Returns:
            ``True`` if the model responded successfully, ``False`` otherwise.
        """
        try:
            p = create_provider(
                provider_name=provider,
                api_key=api_key,
                model=model,
                base_url=base_url,
            )
            # Disable retries so validation completes quickly on failure.
            p.max_retries = 0
        except ValueError as exc:
            log.warning("ModelDiscovery.validate_model: invalid provider %r — %s", provider, exc)
            return False

        try:
            response = p.complete(
                system_prompt=_VALIDATION_SYSTEM,
                user_prompt=_VALIDATION_USER,
                temperature=0.0,
                max_tokens=16,
            )
            is_valid = bool(response.text and response.text.strip())
            log.debug(
                "ModelDiscovery.validate_model: %r/%r valid=%s",
                provider,
                model,
                is_valid,
            )
            return is_valid
        except Exception as exc:
            log.warning(
                "ModelDiscovery.validate_model: %r/%r failed — %s",
                provider,
                model,
                exc,
            )
            return False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _fallback(provider: str) -> list[ModelInfo]:
        """Return the hardcoded fallback list for a provider.

        Returns an empty list for unknown providers rather than raising.
        """
        return list(_FALLBACK_MODELS.get(provider, []))
