"""Provider adapters for the Warlock AI layer.

Exposes a single factory function ``create_provider`` that constructs the
correct ``BaseProvider`` subclass for the requested vendor name.

Supported provider names:
    ``"anthropic"`` — Anthropic Claude via the Messages API
    ``"openai"``    — OpenAI (or compatible) via the Chat Completions API
    ``"gemini"``    — Google Gemini via the generateContent REST API
    ``"ollama"``    — Ollama local inference via the OpenAI-compatible endpoint
"""

from __future__ import annotations

import logging

from warlock.ai.providers.anthropic import AnthropicProvider
from warlock.ai.providers.base import BaseProvider, ProviderResponse
from warlock.ai.providers.gemini import GeminiProvider
from warlock.ai.providers.ollama import OllamaProvider
from warlock.ai.providers.openai_provider import OpenAIProvider

log = logging.getLogger(__name__)

__all__ = [
    "AnthropicProvider",
    "BaseProvider",
    "GeminiProvider",
    "OllamaProvider",
    "OpenAIProvider",
    "ProviderResponse",
    "create_provider",
]

_PROVIDERS: dict[str, type[BaseProvider]] = {
    "anthropic": AnthropicProvider,
    "openai": OpenAIProvider,
    "gemini": GeminiProvider,
    "ollama": OllamaProvider,
}


def create_provider(
    provider_name: str,
    api_key: str,
    model: str,
    base_url: str = "",
) -> BaseProvider:
    """Instantiate a provider adapter by name.

    Args:
        provider_name: One of ``"anthropic"``, ``"openai"``, ``"gemini"``,
            ``"ollama"``.
        api_key: Provider API key.  May be empty for unauthenticated Ollama
            instances.
        model: Model identifier to target (e.g. ``"claude-3-5-sonnet-20241022"``).
        base_url: Optional override for the provider base URL.  Useful for
            proxies, Azure OpenAI endpoints, or a remote Ollama host.

    Returns:
        A concrete ``BaseProvider`` instance ready for ``complete`` /
        ``complete_async`` / ``list_models`` calls.

    Raises:
        ValueError: If ``provider_name`` is not a known provider.
    """
    cls = _PROVIDERS.get(provider_name)
    if not cls:
        known = ", ".join(sorted(_PROVIDERS))
        raise ValueError(f"Unknown provider: {provider_name!r}. Supported providers: {known}")
    log.debug("Creating provider %r with model %r", provider_name, model)
    return cls(api_key=api_key, model=model, base_url=base_url)
