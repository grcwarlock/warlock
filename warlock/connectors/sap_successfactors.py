"""SAP SuccessFactors connector — Layer 1 implementation for HRIS.

Collects user records, employment data, and background certificates via SAP SF OData API v2.
Uses API key authentication.
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

SAP_SF_BASE_URL = "https://api4.successfactors.com"

SAP_SF_ENDPOINTS: list[tuple[str, str]] = [
    ("/odata/v2/User", "sap_sf_users"),
    ("/odata/v2/EmpEmployment", "sap_sf_employment"),
    ("/odata/v2/Background_Certificates", "sap_sf_certificates"),
]


class SAPSuccessFactorsConnector(BaseConnector):
    """Collects compliance telemetry from SAP SuccessFactors OData APIs."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("SAP_SF_API_KEY"):
            errors.append("SAP_SF_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("SAP_SF_API_KEY")
            base_url = self.config.settings.get("base_url", SAP_SF_BASE_URL)
            resp = httpx.get(
                f"{base_url}/odata/v2/User",
                headers=self._headers(token),
                params={"$top": "1", "$format": "json"},
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code == 200
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="sap_successfactors",
            source_type=SourceType.HRIS,
            provider="sap_successfactors",
        )

        token = self.get_secret("SAP_SF_API_KEY")
        base_url = self.config.settings.get("base_url", SAP_SF_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type in SAP_SF_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint)
                    result.events.append(
                        RawEventData(
                            source="sap_successfactors",
                            source_type=SourceType.HRIS,
                            provider="sap_successfactors",
                            event_type=event_type,
                            raw_data={
                                "endpoint": endpoint,
                                "base_url": base_url,
                                "response": data,
                            },
                            observed_at=datetime.now(timezone.utc),
                        )
                    )
                except Exception as e:
                    log.debug("SAP SF %s failed: %s", endpoint, e)
                    result.errors.append(f"{event_type}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "APIKey": token,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _paginate(self, client: object, endpoint: str) -> list:
        """Follow SAP OData $skip-based pagination."""
        all_items: list = []
        skip = 0
        top = 100

        while True:
            resp = client.get(  # type: ignore[attr-defined]
                endpoint,
                params={"$top": top, "$skip": skip, "$format": "json"},
            )
            resp.raise_for_status()
            body = resp.json()
            items = body.get("d", {}).get("results", [])
            all_items.extend(items)

            if len(items) < top:
                break
            skip += top

        return all_items


# Register
registry.register("sap_successfactors", SAPSuccessFactorsConnector)
