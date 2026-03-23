"""Archer GRC connector — Layer 1 implementation for GRC.

Collects content records and application definitions from RSA Archer REST APIs.
Uses username/password session token authentication.
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

ARCHER_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/api/core/content", "archer_content", {"pageSize": "100", "pageNumber": "1"}),
    ("/api/core/system/application", "archer_applications", {"pageSize": "100", "pageNumber": "1"}),
]


class ArcherConnector(BaseConnector):
    """Collects compliance telemetry from RSA Archer REST APIs."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("ARCHER_INSTANCE_URL"):
            errors.append("ARCHER_INSTANCE_URL env var is not set")
        if not self.get_secret("ARCHER_USERNAME"):
            errors.append("ARCHER_USERNAME env var is not set")
        if not self.get_secret("ARCHER_PASSWORD"):
            errors.append("ARCHER_PASSWORD env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            token = self._get_session_token()
            return bool(token)
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="archer",
            source_type=SourceType.GRC,
            provider="archer",
        )

        instance_url = self.get_secret("ARCHER_INSTANCE_URL").rstrip("/")
        session_token = self._get_session_token()

        if not session_token:
            result.errors.append("Failed to obtain Archer session token")
            result.complete("error")
            return result

        headers = {
            "Authorization": f"Archer session-id={session_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        client = httpx.Client(base_url=instance_url, headers=headers, timeout=self.config.timeout_seconds)

        try:
            for endpoint, event_type, params in ARCHER_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint, params)
                    result.events.append(
                        RawEventData(
                            source="archer",
                            source_type=SourceType.GRC,
                            provider="archer",
                            event_type=event_type,
                            raw_data={
                                "endpoint": endpoint,
                                "base_url": instance_url,
                                "response": data,
                            },
                            observed_at=datetime.now(timezone.utc),
                        )
                    )
                except Exception as e:
                    log.debug("Archer %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _get_session_token(self) -> str:
        """Authenticate and obtain an Archer session token."""
        try:
            import httpx

            instance_url = self.get_secret("ARCHER_INSTANCE_URL").rstrip("/")
            username = self.get_secret("ARCHER_USERNAME")
            password = self.get_secret("ARCHER_PASSWORD")
            instance_name = self.config.settings.get("instance_name", "Default")

            resp = httpx.post(
                f"{instance_url}/api/core/security/login",
                json={
                    "InstanceName": instance_name,
                    "Username": username,
                    "UserDomain": "",
                    "Password": password,
                },
                timeout=30,
            )
            resp.raise_for_status()
            body = resp.json()
            return body.get("RequestedObject", {}).get("SessionToken", "")
        except Exception as e:
            log.debug("Archer session token acquisition failed: %s", e)
            return ""

    def _paginate(self, client: object, endpoint: str, params: dict) -> list:
        """Follow Archer page-number-based pagination."""
        all_items: list = []
        current_params = dict(params)
        page = int(current_params.get("pageNumber", 1))

        while True:
            current_params["pageNumber"] = str(page)
            resp = client.get(endpoint, params=current_params)  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()

            items = body.get("RequestedObject", body.get("data", []))
            if isinstance(items, dict):
                items = [items]
            if not isinstance(items, list):
                items = []
            all_items.extend(items)

            total_count = body.get("TotalCount", len(all_items))
            page_size = int(current_params.get("pageSize", 100))
            if len(all_items) >= total_count or len(items) < page_size:
                break
            page += 1

        return all_items


# Register
registry.register("archer", ArcherConnector)
