"""Abstract base class for all AI provider adapters.

Every concrete provider must implement sync completion, async completion, and
model listing.  Response data is normalised into ProviderResponse so the rest
of the pipeline never needs to know which vendor it is talking to.
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT: float = 30.0
DEFAULT_MAX_RETRIES: int = 2


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------


@dataclass
class ProviderResponse:
    """Normalised response returned by every provider implementation."""

    text: str
    model: str
    input_tokens: int | None = None
    output_tokens: int | None = None
    latency_ms: int = 0


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class BaseProvider(ABC):
    """Common interface for Anthropic, OpenAI, Gemini, and Ollama providers.

    Subclasses must implement:
    - ``complete`` — synchronous single completion
    - ``complete_async`` — async completion for batch/concurrent operations
    - ``list_models`` — discover models available on this provider
    """

    def __init__(
        self,
        api_key: str,
        model: str,
        base_url: str = "",
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> None:
        self.api_key = api_key
        self.model = model
        self.base_url = base_url
        self.timeout = timeout
        self.max_retries = max_retries

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ) -> ProviderResponse:
        """Send a synchronous chat completion request.

        Args:
            system_prompt: Instruction context placed before the user turn.
            user_prompt: The user message to complete.
            temperature: Sampling temperature; 0.0 for deterministic output.
            max_tokens: Maximum tokens to generate.

        Returns:
            ProviderResponse with text, model name, token counts, and latency.
        """

    @abstractmethod
    async def complete_async(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ) -> ProviderResponse:
        """Send an async chat completion request for batch operations.

        Args:
            system_prompt: Instruction context placed before the user turn.
            user_prompt: The user message to complete.
            temperature: Sampling temperature; 0.0 for deterministic output.
            max_tokens: Maximum tokens to generate.

        Returns:
            ProviderResponse with text, model name, token counts, and latency.
        """

    @abstractmethod
    def list_models(self) -> list:
        """Discover models available through this provider's API.

        Returns:
            List of ModelInfo objects.  Returns a hardcoded fallback list if
            the upstream API is unavailable.
        """

    # ------------------------------------------------------------------
    # Helpers available to subclasses
    # ------------------------------------------------------------------

    @staticmethod
    def _now_ms() -> int:
        """Current time in milliseconds (monotonic)."""
        return int(time.monotonic() * 1000)

    def _backoff_seconds(self, attempt: int) -> float:
        """Exponential back-off: 1s, 2s, 4s, …"""
        return float(2 ** attempt)
