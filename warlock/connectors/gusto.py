"""Gusto connector — Layer 1 implementation for HR / people operations.

Collects employees (active/terminated), payroll summaries, and company info
via the Gusto API v1 with Bearer OAuth2 token auth.
"""

from __future__ import annotations

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

API_BASE = "https://api.gusto.com/v1"


class GustoConnector(BaseConnector):
    """Collects compliance telemetry from Gusto API."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[gusto]")
        if not self.get_secret("WLK_GUSTO_TOKEN"):
            errors.append("WLK_GUSTO_TOKEN not set")
        if not self.get_secret("WLK_GUSTO_COMPANY_ID"):
            errors.append("WLK_GUSTO_COMPANY_ID not set")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client()
            company_id = self.get_secret("WLK_GUSTO_COMPANY_ID")
            resp = client.get(f"{API_BASE}/companies/{company_id}")
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="gusto",
            source_type=SourceType.HRIS,
            provider="gusto",
        )

        company_id = self.get_secret("WLK_GUSTO_COMPANY_ID")

        self._collect_employees(company_id, result)
        self._collect_payroll(company_id, result)
        self._collect_company(company_id, result)

        result.complete()
        return result

    # -- Client --

    def _client(self) -> httpx.Client:
        token = self.get_secret("WLK_GUSTO_TOKEN")
        return httpx.Client(
            timeout=self.config.timeout_seconds,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )

    # -- Event helpers --

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="gusto",
            source_type=SourceType.HRIS,
            provider="gusto",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_employees(self, company_id: str, result: ConnectorResult) -> None:
        """Collect employees — active and terminated."""
        try:
            client = self._client()
            resp = client.get(f"{API_BASE}/companies/{company_id}/employees")
            resp.raise_for_status()
            employees = resp.json()
            result.events.append(self._raw_event("gusto_employees", {"employees": employees}))
        except Exception as e:
            log.debug("Gusto employees collection failed: %s", e)
            result.errors.append(f"gusto_employees: {e}")

    def _collect_payroll(self, company_id: str, result: ConnectorResult) -> None:
        """Collect payroll summaries."""
        try:
            client = self._client()
            resp = client.get(f"{API_BASE}/companies/{company_id}/payrolls")
            resp.raise_for_status()
            payrolls = resp.json()
            result.events.append(self._raw_event("gusto_payroll", {"payrolls": payrolls}))
        except Exception as e:
            log.debug("Gusto payroll collection failed: %s", e)
            result.errors.append(f"gusto_payroll: {e}")

    def _collect_company(self, company_id: str, result: ConnectorResult) -> None:
        """Collect company info."""
        try:
            client = self._client()
            resp = client.get(f"{API_BASE}/companies/{company_id}")
            resp.raise_for_status()
            company = resp.json()
            result.events.append(self._raw_event("gusto_company", {"company": company}))
        except Exception as e:
            log.debug("Gusto company collection failed: %s", e)
            result.errors.append(f"gusto_company: {e}")


# Register
registry.register("gusto", GustoConnector)
