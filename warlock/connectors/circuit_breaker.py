"""Circuit breaker pattern for connector resilience.

Prevents cascading failures by tracking consecutive errors and
temporarily disabling a connector that is consistently failing.

States:
  - **closed** — normal operation, requests pass through.
  - **open** — too many failures; requests are rejected immediately.
  - **half_open** — recovery window; one probe request allowed.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, TypeVar

log = logging.getLogger(__name__)

T = TypeVar("T")


class CircuitOpenError(Exception):
    """Raised when the circuit breaker is open and rejecting calls."""

    def __init__(self, name: str, retry_after: float) -> None:
        self.name = name
        self.retry_after = retry_after
        super().__init__(f"Circuit breaker '{name}' is open — retry after {retry_after:.0f}s")


class CircuitBreaker:
    """Simple three-state circuit breaker.

    Parameters
    ----------
    name:
        Identifier (usually the connector name).
    failure_threshold:
        Consecutive failures before the circuit opens.
    recovery_timeout:
        Seconds before the circuit transitions from open to half-open.
    """

    def __init__(
        self,
        name: str = "default",
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
    ) -> None:
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout

        self._failure_count: int = 0
        self._last_failure_time: float = 0.0
        self._state: str = "closed"

    @property
    def state(self) -> str:
        """Current state: ``closed``, ``open``, or ``half_open``."""
        if self._state == "open":
            elapsed = time.monotonic() - self._last_failure_time
            if elapsed >= self.recovery_timeout:
                self._state = "half_open"
        return self._state

    def call(self, func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        """Execute *func* through the circuit breaker.

        Raises :class:`CircuitOpenError` when the circuit is open.
        """
        current = self.state

        if current == "open":
            retry_after = self.recovery_timeout - (time.monotonic() - self._last_failure_time)
            raise CircuitOpenError(self.name, max(retry_after, 0))

        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception:
            self._on_failure()
            raise

    def _on_success(self) -> None:
        if self._state == "half_open":
            log.info("Circuit breaker '%s' recovered — closing", self.name)
        self._failure_count = 0
        self._state = "closed"

    def _on_failure(self) -> None:
        self._failure_count += 1
        self._last_failure_time = time.monotonic()

        if self._failure_count >= self.failure_threshold:
            self._state = "open"
            log.warning(
                "Circuit breaker '%s' opened after %d consecutive failures",
                self.name,
                self._failure_count,
            )

    def reset(self) -> None:
        """Force-reset to closed state."""
        self._failure_count = 0
        self._state = "closed"
