"""Venafi connector — Layer 1 implementation for CUSTOM (certificate management).

Collects certificate inventory and configuration data from Venafi Trust Protection
Platform using API key authentication against the VEDsdk REST API.
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

VENAFI_BASE_URL = "https://venafi.example.com"

ENDPOINTS: list[tuple[str, str, dict]] = [
    (
        "/vedsdk/certificates",
        "venafi_certificates",
        {"Limit": "100", "Offset": "0"},
    ),
    (
        "/vedsdk/config",
        "venafi_config",
        {},
    ),
]


class VenafiConnector(BaseConnector):
    """Collects certificate telemetry from Venafi Trust Protection Platform."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("VENAFI_API_KEY"):
            errors.append("VENAFI_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("VENAFI_API_KEY")
            base_url = self.config.settings.get("base_url", VENAFI_BASE_URL)
            resp = httpx.get(
                f"{base_url}/vedsdk/certificates",
                headers=self._headers(token),
                params={"Limit": "1", "Offset": "0"},
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
            source="venafi",
            source_type=SourceType.CUSTOM,
            provider="venafi",
        )

        token = self.get_secret("VENAFI_API_KEY")
        base_url = self.config.settings.get("base_url", VENAFI_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, params in ENDPOINTS:
                try:
                    if endpoint == "/vedsdk/certificates":
                        data = self._paginate_certs(client, endpoint, params)
                    else:
                        resp = client.get(endpoint, params=params)  # type: ignore[attr-defined]
                        resp.raise_for_status()
                        data = [resp.json()] if resp.content else []
                    result.events.append(
                        RawEventData(
                            source="venafi",
                            source_type=SourceType.CUSTOM,
                            provider="venafi",
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
                    log.debug("Venafi %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "X-Venafi-Api-Key": token,
            "Content-Type": "application/json",
        }

    def _paginate_certs(self, client: object, endpoint: str, params: dict) -> list:
        """Follow Venafi offset-based pagination for certificate listings."""
        all_items: list = []
        limit = int(params.get("Limit", 100))
        offset = 0
        current_params = dict(params)

        while True:
            current_params["Offset"] = str(offset)
            resp = client.get(endpoint, params=current_params)  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()

            # Venafi returns {"Certificates": [...], "TotalCount": N}
            if isinstance(body, list):
                items = body
            else:
                items = body.get("Certificates", body.get("items", []))

            all_items.extend(items)

            if len(items) < limit:
                break
            offset += limit

        return all_items


# Register
registry.register("venafi", VenafiConnector)
