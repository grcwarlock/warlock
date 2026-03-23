"""Snyk Container connector — Layer 1 implementation for CONTAINER_SECURITY.

Collects container images and issues from the Snyk REST API.
Authenticates with a bearer token (SNYK_TOKEN).
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

SNYK_CONTAINER_BASE_URL = "https://api.snyk.io"


class SnykContainerConnector(BaseConnector):
    """Collects container security telemetry from the Snyk API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("SNYK_TOKEN"):
            errors.append("SNYK_TOKEN env var is not set")
        if not self.config.settings.get("org_id"):
            errors.append("org_id must be set in connector settings")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("SNYK_TOKEN")
            base_url = self.config.settings.get("base_url", SNYK_CONTAINER_BASE_URL)
            resp = httpx.get(
                f"{base_url}/v1/user/me",
                headers=self._headers(token),
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code in (200, 401)
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="snyk_container",
            source_type=SourceType.CONTAINER_SECURITY,
            provider="snyk_container",
        )

        token = self.get_secret("SNYK_TOKEN")
        org_id = self.config.settings.get("org_id", "")
        base_url = self.config.settings.get("base_url", SNYK_CONTAINER_BASE_URL)
        headers = self._headers(token)

        endpoints: list[tuple[str, str]] = [
            (f"/v1/org/{org_id}/container/images", "snyk_container_images"),
            (f"/v1/org/{org_id}/container/issues", "snyk_container_issues"),
        ]

        client = httpx.Client(base_url=base_url, headers=headers, timeout=self.config.timeout_seconds)

        try:
            for endpoint, event_type in endpoints:
                try:
                    resp = client.get(endpoint)
                    resp.raise_for_status()
                    body = resp.json()
                    items = body if isinstance(body, list) else body.get("results", body.get("issues", []))
                    result.events.append(
                        RawEventData(
                            source="snyk_container",
                            source_type=SourceType.CONTAINER_SECURITY,
                            provider="snyk_container",
                            event_type=event_type,
                            raw_data={
                                "endpoint": endpoint,
                                "base_url": base_url,
                                "org_id": org_id,
                                "response": items,
                            },
                            observed_at=datetime.now(timezone.utc),
                        )
                    )
                except Exception as e:
                    log.debug("Snyk Container %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"token {token}",
            "Content-Type": "application/json",
        }


# Register
registry.register("snyk_container", SnykContainerConnector)
