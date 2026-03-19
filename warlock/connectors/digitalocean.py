"""DigitalOcean connector — Layer 1 implementation for cloud infrastructure.

Collects firewalls, droplets, spaces, databases, Kubernetes clusters,
load balancers, and domain records via the DigitalOcean API v2.
Uses httpx with Bearer token authentication.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from warlock.connectors.base import (
    BaseConnector,
    ConnectorConfig,
    ConnectorResult,
    RawEventData,
    SourceType,
    registry,
)

log = logging.getLogger(__name__)

BASE_URL = "https://api.digitalocean.com/v2"

# (path, event_type, response_key) — response_key is the top-level JSON key
# holding the list of resources returned by the API.
DO_ENDPOINTS: list[tuple[str, str, str]] = [
    ("/v2/firewalls", "do_firewalls", "firewalls"),
    ("/v2/droplets", "do_droplets", "droplets"),
    ("/v2/databases", "do_databases", "databases"),
    ("/v2/kubernetes/clusters", "do_kubernetes", "kubernetes_clusters"),
    ("/v2/load_balancers", "do_load_balancers", "load_balancers"),
    ("/v2/domains", "do_domains", "domains"),
]


class DigitalOceanConnector(BaseConnector):
    """Collects compliance telemetry from the DigitalOcean API v2."""

    def validate(self) -> list[str]:
        errors = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append(
                "httpx not installed. Install with: pip install warlock[digitalocean]"
            )
        if not self.get_secret("WLK_DIGITALOCEAN_TOKEN"):
            errors.append("WLK_DIGITALOCEAN_TOKEN env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("WLK_DIGITALOCEAN_TOKEN")
            resp = httpx.get(
                f"{BASE_URL}/account",
                headers=self._headers(token),
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="digitalocean",
            source_type=SourceType.CLOUD,
            provider="digitalocean",
        )

        token = self.get_secret("WLK_DIGITALOCEAN_TOKEN")
        headers = self._headers(token)

        client = httpx.Client(
            base_url=BASE_URL,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, response_key in DO_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint, response_key)
                    result.events.append(RawEventData(
                        source="digitalocean",
                        source_type=SourceType.CLOUD,
                        provider="digitalocean",
                        event_type=event_type,
                        raw_data={
                            "endpoint": endpoint,
                            "response": data,
                        },
                        observed_at=datetime.now(timezone.utc),
                    ))
                except Exception as e:
                    log.debug("DigitalOcean %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")

            # Spaces — uses a separate endpoint (S3-compatible listing)
            try:
                spaces = self._collect_spaces(client)
                result.events.append(RawEventData(
                    source="digitalocean",
                    source_type=SourceType.CLOUD,
                    provider="digitalocean",
                    event_type="do_spaces",
                    raw_data={
                        "endpoint": "/v2/spaces",
                        "response": spaces,
                    },
                    observed_at=datetime.now(timezone.utc),
                ))
            except Exception as e:
                log.debug("DigitalOcean spaces failed: %s", e)
                result.errors.append(f"spaces: {e}")

        finally:
            client.close()

        result.complete()
        return result

    # -- Helpers --

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _paginate(
        self, client, endpoint: str, response_key: str
    ) -> list:
        """Follow DigitalOcean page-based pagination."""
        all_items: list = []
        page = 1
        per_page = 200

        while True:
            resp = client.get(
                endpoint, params={"page": page, "per_page": per_page}
            )
            resp.raise_for_status()
            body = resp.json()

            items = body.get(response_key, [])
            all_items.extend(items)

            # Check for next page via links.pages.next
            links = body.get("links", {})
            pages = links.get("pages", {})
            if not pages.get("next"):
                break
            page += 1

        return all_items

    def _collect_spaces(self, client) -> list:
        """Collect Spaces (object storage buckets) via the API.

        The DO API exposes Spaces listing at /v2/spaces in newer versions.
        Falls back gracefully if the endpoint is unavailable.
        """
        all_items: list = []
        page = 1
        per_page = 200

        while True:
            resp = client.get(
                "/v2/spaces", params={"page": page, "per_page": per_page}
            )
            resp.raise_for_status()
            body = resp.json()

            items = body.get("spaces", [])
            all_items.extend(items)

            links = body.get("links", {})
            pages = links.get("pages", {})
            if not pages.get("next"):
                break
            page += 1

        return all_items


# Register
registry.register("digitalocean", DigitalOceanConnector)
