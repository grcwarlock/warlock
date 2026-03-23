"""BitSight connector — Layer 1 implementation for third-party risk management.

Collects company ratings, risk vectors, findings, and portfolio companies
via the BitSight API with Basic auth (token as username, empty password).
"""

from __future__ import annotations

import base64
import logging
from datetime import datetime, timezone

from warlock.connectors.base import (
    BaseConnector,
    ConnectorResult,
    RawEventData,
    SourceType,
    registry,
)

log = logging.getLogger(__name__)

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]

API_BASE = "https://api.bitsighttech.com/ratings/v1"


class BitSightConnector(BaseConnector):
    """Collects compliance telemetry from BitSight API."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[bitsight]")
        if not self.get_secret("WLK_BITSIGHT_TOKEN"):
            errors.append("WLK_BITSIGHT_TOKEN not set")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client()
            resp = client.get(f"{API_BASE}/portfolio")
            return resp.status_code == 200
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="bitsight",
            source_type=SourceType.THIRD_PARTY_RISK,
            provider="bitsight",
        )

        self._collect_ratings(result)
        self._collect_risk_vectors(result)
        self._collect_findings(result)
        self._collect_portfolio(result)

        result.complete()
        return result

    # -- Client --

    def _client(self) -> httpx.Client:
        token = self.get_secret("WLK_BITSIGHT_TOKEN")
        auth_str = base64.b64encode(f"{token}:".encode()).decode()
        return httpx.Client(
            timeout=self.config.timeout_seconds,
            headers={"Authorization": f"Basic {auth_str}", "Accept": "application/json"},
        )

    # -- Event helpers --

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="bitsight",
            source_type=SourceType.THIRD_PARTY_RISK,
            provider="bitsight",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_ratings(self, result: ConnectorResult) -> None:
        """Collect company security ratings."""
        try:
            client = self._client()
            resp = client.get(f"{API_BASE}/companies")
            resp.raise_for_status()
            companies = resp.json().get("results", [])
            result.events.append(self._raw_event("bitsight_ratings", {"companies": companies}))
        except Exception as e:
            log.debug("BitSight ratings collection failed: %s", e)
            result.errors.append(f"bitsight_ratings: {e}")

    def _collect_risk_vectors(self, result: ConnectorResult) -> None:
        """Collect risk vector grades (botnet, open ports, patching, etc.)."""
        try:
            client = self._client()
            resp = client.get(f"{API_BASE}/companies/risk-vectors")
            resp.raise_for_status()
            vectors = resp.json().get("risk_vectors", [])
            result.events.append(
                self._raw_event("bitsight_risk_vectors", {"risk_vectors": vectors})
            )
        except Exception as e:
            log.debug("BitSight risk vectors collection failed: %s", e)
            result.errors.append(f"bitsight_risk_vectors: {e}")

    def _collect_findings(self, result: ConnectorResult) -> None:
        """Collect security findings across monitored companies."""
        try:
            client = self._client()
            resp = client.get(f"{API_BASE}/findings", params={"limit": "500"})
            resp.raise_for_status()
            findings = resp.json().get("results", [])
            result.events.append(self._raw_event("bitsight_findings", {"findings": findings}))
        except Exception as e:
            log.debug("BitSight findings collection failed: %s", e)
            result.errors.append(f"bitsight_findings: {e}")

    def _collect_portfolio(self, result: ConnectorResult) -> None:
        """Collect portfolio companies and their ratings."""
        try:
            client = self._client()
            resp = client.get(f"{API_BASE}/portfolio")
            resp.raise_for_status()
            portfolio = resp.json().get("results", [])
            result.events.append(self._raw_event("bitsight_portfolio", {"companies": portfolio}))
        except Exception as e:
            log.debug("BitSight portfolio collection failed: %s", e)
            result.errors.append(f"bitsight_portfolio: {e}")


# Register
registry.register("bitsight", BitSightConnector)
