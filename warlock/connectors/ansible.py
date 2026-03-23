"""Ansible/AWX connector — Layer 1 implementation for INFRASTRUCTURE.

Collects hosts, inventories, and job templates via Ansible Tower / AWX REST API v2.
Uses Bearer token authentication.
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

ANSIBLE_BASE_URL = "https://your-awx-instance.example.com"

ANSIBLE_ENDPOINTS: list[tuple[str, str]] = [
    ("/api/v2/hosts", "ansible_hosts"),
    ("/api/v2/inventories", "ansible_inventories"),
    ("/api/v2/job_templates", "ansible_job_templates"),
]


class AnsibleConnector(BaseConnector):
    """Collects compliance telemetry from Ansible Tower / AWX APIs."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("ANSIBLE_AWX_TOKEN"):
            errors.append("ANSIBLE_AWX_TOKEN env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("ANSIBLE_AWX_TOKEN")
            base_url = self.config.settings.get("base_url", ANSIBLE_BASE_URL)
            resp = httpx.get(
                f"{base_url}/api/v2/ping/",
                headers=self._headers(token),
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
            source="ansible",
            source_type=SourceType.INFRASTRUCTURE,
            provider="ansible",
        )

        token = self.get_secret("ANSIBLE_AWX_TOKEN")
        base_url = self.config.settings.get("base_url", ANSIBLE_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type in ANSIBLE_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint)
                    result.events.append(
                        RawEventData(
                            source="ansible",
                            source_type=SourceType.INFRASTRUCTURE,
                            provider="ansible",
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
                    log.debug("Ansible %s failed: %s", endpoint, e)
                    result.errors.append(f"{event_type}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _paginate(self, client: object, endpoint: str) -> list:
        """Follow AWX cursor-based pagination via 'next' URL."""
        all_items: list = []
        url: str | None = endpoint

        while url:
            if url.startswith("http"):
                import httpx

                resp = httpx.get(
                    url,
                    headers=client.headers,  # type: ignore[attr-defined]
                    timeout=30,
                )
            else:
                resp = client.get(url, params={"page_size": 200})  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()
            all_items.extend(body.get("results", []))
            url = body.get("next")

        return all_items


# Register
registry.register("ansible", AnsibleConnector)
