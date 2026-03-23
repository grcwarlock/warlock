"""DigiCert connector — Layer 1 implementation for CUSTOM (certificate management).

Collects certificate order and certificate detail data from the DigiCert
CertCentral REST API using API key authentication.
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

DIGICERT_BASE_URL = "https://www.digicert.com"

ENDPOINTS: list[tuple[str, str, dict]] = [
    (
        "/services/v2/order/certificate",
        "digicert_orders",
        {"limit": "100", "offset": "0"},
    ),
    (
        "/services/v2/certificate",
        "digicert_certificates",
        {"limit": "100", "offset": "0"},
    ),
]


class DigiCertConnector(BaseConnector):
    """Collects certificate telemetry from DigiCert CertCentral API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("DIGICERT_API_KEY"):
            errors.append("DIGICERT_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("DIGICERT_API_KEY")
            base_url = self.config.settings.get("base_url", DIGICERT_BASE_URL)
            resp = httpx.get(
                f"{base_url}/services/v2/order/certificate",
                headers=self._headers(token),
                params={"limit": "1", "offset": "0"},
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="digicert",
            source_type=SourceType.CUSTOM,
            provider="digicert",
        )

        token = self.get_secret("DIGICERT_API_KEY")
        base_url = self.config.settings.get("base_url", DIGICERT_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, params in ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint, params)
                    result.events.append(
                        RawEventData(
                            source="digicert",
                            source_type=SourceType.CUSTOM,
                            provider="digicert",
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
                    log.debug("DigiCert %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "X-DC-DEVKEY": token,
            "Content-Type": "application/json",
        }

    def _paginate(self, client: object, endpoint: str, params: dict) -> list:
        """Follow DigiCert offset-based pagination."""
        all_items: list = []
        limit = int(params.get("limit", 100))
        offset = 0
        current_params = dict(params)

        while True:
            current_params["offset"] = str(offset)
            resp = client.get(endpoint, params=current_params)  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()

            # DigiCert wraps results in {"orders": [...]} or {"certificates": [...]}
            if isinstance(body, list):
                items = body
            else:
                # Try common keys
                for key in ("orders", "certificates", "items", "data", "results"):
                    if key in body:
                        items = body[key]
                        break
                else:
                    items = []

            all_items.extend(items)

            if len(items) < limit:
                break
            offset += limit

        return all_items


# Register
registry.register("digicert", DigiCertConnector)
