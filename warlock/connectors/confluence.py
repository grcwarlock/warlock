"""Confluence connector — Layer 1 implementation for GRC.

Collects pages and page versions from Confluence Cloud REST API v2.
Uses Basic auth with user email and API token.
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


class ConfluenceConnector(BaseConnector):
    """Collects compliance telemetry from Confluence Cloud REST API."""

    def validate(self) -> list[str]:
        errors = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed. Install with: pip install warlock[confluence]")
        if not self.get_secret("WLK_CONFLUENCE_URL"):
            errors.append("WLK_CONFLUENCE_URL env var is not set")
        if not self.get_secret("WLK_CONFLUENCE_USER"):
            errors.append("WLK_CONFLUENCE_USER env var is not set")
        if not self.get_secret("WLK_CONFLUENCE_API_TOKEN"):
            errors.append("WLK_CONFLUENCE_API_TOKEN env var is not set")
        if not self.config.settings.get("space_keys"):
            errors.append("'space_keys' must be set in connector settings (list of space keys)")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            base_url = self.get_secret("WLK_CONFLUENCE_URL").rstrip("/")
            resp = httpx.get(
                f"{base_url}/wiki/api/v2/spaces",
                params={"limit": "1"},
                auth=(
                    self.get_secret("WLK_CONFLUENCE_USER"),
                    self.get_secret("WLK_CONFLUENCE_API_TOKEN"),
                ),
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
            source="confluence",
            source_type=SourceType.GRC,
            provider="confluence",
        )

        base_url = self.get_secret("WLK_CONFLUENCE_URL").rstrip("/")
        auth = (self.get_secret("WLK_CONFLUENCE_USER"), self.get_secret("WLK_CONFLUENCE_API_TOKEN"))
        space_keys: list[str] = self.config.settings.get("space_keys", [])

        client = httpx.Client(
            base_url=base_url,
            auth=auth,
            timeout=self.config.timeout_seconds,
        )

        try:
            for space_key in space_keys:
                # Collect pages for this space
                try:
                    pages = self._paginate_pages(client, space_key)
                    result.events.append(
                        RawEventData(
                            source="confluence",
                            source_type=SourceType.GRC,
                            provider="confluence",
                            event_type="confluence_pages",
                            raw_data={
                                "space_key": space_key,
                                "pages": pages,
                            },
                            observed_at=datetime.now(timezone.utc),
                        )
                    )

                    # Collect versions for each page
                    for page in pages:
                        page_id = page.get("id", "")
                        if not page_id:
                            continue
                        try:
                            versions = self._get_page_versions(client, page_id)
                            result.events.append(
                                RawEventData(
                                    source="confluence",
                                    source_type=SourceType.GRC,
                                    provider="confluence",
                                    event_type="confluence_page_versions",
                                    raw_data={
                                        "space_key": space_key,
                                        "page_id": page_id,
                                        "page_title": page.get("title", ""),
                                        "versions": versions,
                                    },
                                    observed_at=datetime.now(timezone.utc),
                                )
                            )
                        except Exception as e:
                            log.debug("Confluence page versions for %s failed: %s", page_id, e)
                            result.errors.append(f"page_versions/{page_id}: {e}")

                except Exception as e:
                    log.debug("Confluence pages for space %s failed: %s", space_key, e)
                    result.errors.append(f"pages/{space_key}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _paginate_pages(self, client, space_key: str) -> list:
        """Paginate Confluence v2 pages endpoint."""
        all_pages: list = []
        url = f"/wiki/api/v2/spaces/{space_key}/pages"
        params: dict[str, str] = {"limit": "100"}

        while url:
            resp = client.get(url, params=params)
            resp.raise_for_status()
            body = resp.json()
            results = body.get("results", [])
            all_pages.extend(results)

            # Confluence v2 uses _links.next for pagination
            next_link = body.get("_links", {}).get("next")
            if next_link:
                url = next_link
                params = {}
            else:
                break

        return all_pages

    def _get_page_versions(self, client, page_id: str) -> list:
        """Fetch versions for a single page."""
        resp = client.get(
            f"/wiki/api/v2/pages/{page_id}/versions",
            params={"limit": "25"},
        )
        resp.raise_for_status()
        return resp.json().get("results", [])


# Register
registry.register("confluence", ConfluenceConnector)
