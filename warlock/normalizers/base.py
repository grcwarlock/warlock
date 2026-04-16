"""Layer 2 — Normalization.

BaseNormalizer defines the contract for transforming RawEventData → FindingData.
Each source type registers a normalizer that knows how to extract structure
from that source's raw payloads.
"""

from __future__ import annotations

import hashlib
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from warlock.connectors.base import RawEventData, SourceType
from warlock.utils.pii import scrub_finding

log = logging.getLogger(__name__)

# F25: module-level counter for PII scrub failures. Exposed so that
# observability tooling can scrape it. Reset only on process restart.
_pii_scrub_failure_count: int = 0


def get_pii_scrub_failure_count() -> int:
    """Return the running count of PII scrub failures since process start."""
    return _pii_scrub_failure_count


# ---------------------------------------------------------------------------
# Finding — the universal normalized unit
# ---------------------------------------------------------------------------


@dataclass
class FindingData:
    raw_event_id: str

    # What was observed
    observation_type: (
        str  # misconfiguration, vulnerability, alert, policy_violation, access_anomaly, inventory
    )
    title: str
    detail: dict[str, Any]

    # What resource
    resource_id: str = ""
    resource_type: str = ""
    resource_name: str = ""
    account_id: str = ""
    region: str = ""

    # Source lineage
    source: str = ""
    source_type: SourceType = SourceType.CUSTOM
    provider: str = ""

    # Severity as reported by source
    severity: str = "info"  # critical, high, medium, low, info
    confidence: float = 1.0

    # Time
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # PII
    pii_detected: bool = False

    # Identity
    id: str = field(default_factory=lambda: str(uuid4()))

    @property
    def sha256(self) -> str:
        content = json.dumps(
            {
                "type": self.observation_type,
                "detail": self.detail,
                "resource_id": self.resource_id,
                "resource_type": self.resource_type,
            },
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(content.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Normalizer contract
# ---------------------------------------------------------------------------


class BaseNormalizer(ABC):
    """Transform raw events from a specific source into Findings.

    One normalizer per (source, event_type) combination. A single raw event
    can produce zero, one, or many findings — e.g., an IAM credential report
    produces one finding per user.
    """

    @abstractmethod
    def can_handle(self, raw_event: RawEventData) -> bool:
        """Return True if this normalizer knows how to process this event."""
        ...

    @abstractmethod
    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        """Transform a raw event into zero or more findings."""
        ...


# ---------------------------------------------------------------------------
# Normalizer registry
# ---------------------------------------------------------------------------


class NormalizerRegistry:
    """Finds the right normalizer for a given raw event."""

    _MAX_FAILURES: int = 100

    def __init__(self) -> None:
        self._normalizers: list[BaseNormalizer] = []
        self._failure_count: int = 0
        self._failures: list[dict[str, Any]] = []

    def register(self, normalizer: BaseNormalizer) -> None:
        self._normalizers.append(normalizer)

    def list_normalizers(self) -> list[BaseNormalizer]:
        """Return the list of registered normalizers (public API)."""
        return list(self._normalizers)

    @property
    def failure_count(self) -> int:
        """Total number of normalization failures since last reset."""
        return self._failure_count

    @property
    def failures(self) -> list[dict[str, Any]]:
        """Last 100 failure records (event_id, error, normalizer)."""
        return list(self._failures)

    def reset_failures(self) -> None:
        """Clear the failure counter and history."""
        self._failure_count = 0
        self._failures.clear()

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        if raw_event.raw_data is None:
            log.warning(
                "Skipping event %s with null raw_data (source=%s, event_type=%s)",
                raw_event.id,
                raw_event.source,
                raw_event.event_type,
            )
            return []
        for normalizer in self._normalizers:
            if normalizer.can_handle(raw_event):
                try:
                    findings = normalizer.normalize(raw_event)
                except Exception as exc:
                    log.exception(
                        "Normalizer %s failed on event %s",
                        type(normalizer).__name__,
                        raw_event.id,
                    )
                    self._failure_count += 1
                    self._failures.append(
                        {
                            "event_id": raw_event.id,
                            "normalizer": type(normalizer).__name__,
                            "error": str(exc),
                        }
                    )
                    if len(self._failures) > self._MAX_FAILURES:
                        self._failures = self._failures[-self._MAX_FAILURES :]
                    return []
                # PII scrubbing runs outside the normalizer try/except so a
                # scrub failure doesn't discard the entire event batch.
                # N2 fix: in non-development env we RAISE so the pipeline run
                # is marked failed and operators can investigate; in dev we
                # drop and continue. Either way the failure is counted.
                from warlock.config import get_settings

                env = get_settings().env
                scrubbed: list[FindingData] = []
                for f in findings:
                    try:
                        scrubbed.append(scrub_finding(f))
                    except Exception as exc:
                        global _pii_scrub_failure_count
                        _pii_scrub_failure_count += 1
                        log.error(
                            "PII scrub failed for finding %s — dropping (total failures: %d)",
                            f.id,
                            _pii_scrub_failure_count,
                        )
                        if env != "development":
                            raise RuntimeError(
                                f"PII scrub failed in env={env} — refusing to "
                                f"persist potentially unscrubbed findings (finding_id={f.id})"
                            ) from exc
                        # Development: drop rather than persist unscrubbed data
                return scrubbed
        log.warning(
            "No normalizer found for source=%s event_type=%s",
            raw_event.source,
            raw_event.event_type,
        )
        return []


# Singleton registry
registry = NormalizerRegistry()
