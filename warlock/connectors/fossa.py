"""FOSSA connector — Layer 1 implementation for CODE.

Collects projects, issues, and dependencies from the FOSSA REST API.
Authenticates with a bearer API key.
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

FOSSA_BASE_URL = "https://app.fossa.com"

FOSSA_ENDPOINTS: list[tuple[str, str]] = [
    ("/api/v2/projects", "fossa_projects"),
    ("/api/v2/issues", "fossa_issues"),
    ("/api/v2/dependencies", "fossa_dependencies"),
]


class FossaConnector(BaseConnector):
    """Collects compliance telemetry from the FOSSA REST API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("FOSSA_API_KEY"):
            errors.append("FOSSA_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("FOSSA_API_KEY")
            base_url = self.config.settings.get("base_url", FOSSA_BASE_URL)
            resp = httpx.get(
                f"{base_url}/api/v2/projects",
                headers=self._headers(token),
                params={"count": "1"},
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code in (200, 401, 403)
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="fossa",
            source_type=SourceType.CODE,
            provider="fossa",
        )

        token = self.get_secret("FOSSA_API_KEY")
        base_url = self.config.settings.get("base_url", FOSSA_BASE_URL)
        headers = self._headers(token)
        client = httpx.Client(
            base_url=base_url, headers=headers, timeout=self.config.timeout_seconds
        )

        try:
            for endpoint, event_type in FOSSA_ENDPOINTS:
                try:
                    resp = client.get(endpoint)
                    resp.raise_for_status()
                    body = resp.json()
                    items = (
                        body
                        if isinstance(body, list)
                        else body.get("projects", body.get("issues", body.get("dependencies", [])))
                    )
                    result.events.append(
                        RawEventData(
                            source="fossa",
                            source_type=SourceType.CODE,
                            provider="fossa",
                            event_type=event_type,
                            raw_data={
                                "endpoint": endpoint,
                                "base_url": base_url,
                                "response": items,
                            },
                            observed_at=datetime.now(timezone.utc),
                        )
                    )
                except Exception as e:
                    log.debug("FOSSA %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }


# Register
registry.register("fossa", FossaConnector)
