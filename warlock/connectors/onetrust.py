"""OneTrust connector — Layer 1 implementation for GRC / privacy.

Collects assessments, data maps, DSAR requests, and consent records
from the OneTrust REST API. Uses OAuth 2.0 client credentials for auth.
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

# (endpoint, event_type, response_key)
ONETRUST_ENDPOINTS: list[tuple[str, str, str]] = [
    ("/api/assessment/v2/assessments", "onetrust_assessments", "content"),
    ("/api/datamap/v2/data-maps", "onetrust_data_maps", "content"),
    ("/api/dsar/v3/requests", "onetrust_dsar_requests", "content"),
    ("/api/consent/v2/consent-receipts", "onetrust_consent_records", "content"),
]


class OneTrustConnector(BaseConnector):
    """Collects privacy and GRC telemetry from OneTrust APIs."""

    def validate(self) -> list[str]:
        errors = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed. Install with: pip install warlock[onetrust]")
        if not self.get_secret("WLK_ONETRUST_CLIENT_ID"):
            errors.append("WLK_ONETRUST_CLIENT_ID env var is not set")
        if not self.get_secret("WLK_ONETRUST_CLIENT_SECRET"):
            errors.append("WLK_ONETRUST_CLIENT_SECRET env var is not set")
        if not self.get_secret("WLK_ONETRUST_HOST"):
            errors.append("WLK_ONETRUST_HOST env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            token = self._obtain_token()
            return bool(token)
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="onetrust",
            source_type=SourceType.GRC,
            provider="onetrust",
        )

        host = self.get_secret("WLK_ONETRUST_HOST").rstrip("/")
        base_url = f"https://{host}" if not host.startswith("https://") else host

        try:
            token = self._obtain_token()
        except Exception as e:
            result.errors.append(f"oauth_token: {e}")
            result.complete("error")
            return result

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, response_key in ONETRUST_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint, response_key)
                    result.events.append(RawEventData(
                        source="onetrust",
                        source_type=SourceType.GRC,
                        provider="onetrust",
                        event_type=event_type,
                        raw_data={
                            "endpoint": endpoint,
                            "response": data,
                        },
                        observed_at=datetime.now(timezone.utc),
                    ))
                except Exception as e:
                    log.debug("OneTrust %s failed: %s", endpoint, e)
                    result.errors.append(f"{event_type}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _obtain_token(self) -> str:
        """Fetch an OAuth 2.0 bearer token from OneTrust."""
        import httpx

        host = self.get_secret("WLK_ONETRUST_HOST").rstrip("/")
        base = f"https://{host}" if not host.startswith("https://") else host
        token_url = f"{base}/api/access/v1/oauth/token"

        resp = httpx.post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self.get_secret("WLK_ONETRUST_CLIENT_ID"),
                "client_secret": self.get_secret("WLK_ONETRUST_CLIENT_SECRET"),
            },
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    def _paginate(self, client, endpoint: str, response_key: str) -> list:
        """Paginate OneTrust API using page number."""
        all_items: list = []
        page = 0

        while True:
            resp = client.get(endpoint, params={"size": "100", "page": str(page)})
            resp.raise_for_status()
            body = resp.json()

            items = body.get(response_key, [])
            if not items:
                break
            all_items.extend(items)

            # Check if there are more pages
            total_pages = body.get("page", {}).get("totalPages", 1)
            page += 1
            if page >= total_pages:
                break

        return all_items


# Register
registry.register("onetrust", OneTrustConnector)
