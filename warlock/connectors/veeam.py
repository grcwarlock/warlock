"""Veeam Backup & Replication connector — Layer 1 implementation for Backup.

Collects backup jobs, sessions, and restore points via the Veeam REST API.
Uses OAuth2 password grant for authentication.
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

VEEAM_ENDPOINTS: list[tuple[str, str]] = [
    ("/api/v1/jobs", "veeam_backup_jobs"),
    (
        "/api/v1/sessions?limit=100&orderColumn=endTime&orderAsc=false",
        "veeam_backup_sessions",
    ),
    ("/api/v1/restorePoints?limit=100", "veeam_restore_points"),
]


class VeeamConnector(BaseConnector):
    """Collects backup telemetry from Veeam Backup & Replication REST API."""

    def validate(self) -> list[str]:
        errors = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed. Install with: pip install httpx")
        if not self._get_base_url():
            errors.append(
                "Veeam base_url not configured "
                "(set WLK_VEEAM_BASE_URL or config.settings.base_url)"
            )
        if not self._get_username():
            errors.append(
                "Veeam username not configured "
                "(set WLK_VEEAM_USERNAME or config.settings.username)"
            )
        if not self._get_password():
            errors.append(
                "Veeam password not configured "
                "(set WLK_VEEAM_PASSWORD or config.settings.password)"
            )
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self._acquire_token()
            if not token:
                return False
            base_url = self._get_base_url()
            resp = httpx.get(
                f"{base_url}/api/v1/jobs",
                headers=self._auth_headers(token),
                params={"limit": "1"},
                timeout=30,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="veeam",
            source_type=SourceType.BACKUP,
            provider="veeam",
        )

        token = self._acquire_token()
        if not token:
            result.errors.append("Failed to acquire Veeam access token")
            result.complete("error")
            return result

        base_url = self._get_base_url()
        headers = self._auth_headers(token)
        timeout = self.config.timeout_seconds

        for endpoint, event_type in VEEAM_ENDPOINTS:
            try:
                url = f"{base_url}{endpoint}"
                resp = httpx.get(url, headers=headers, timeout=timeout)
                resp.raise_for_status()
                body = resp.json()

                # Veeam returns data directly as a list or in a "data" key
                if isinstance(body, list):
                    records = body
                else:
                    records = body.get("data", body.get("value", []))
                    if isinstance(records, dict):
                        records = [records]

                result.events.append(RawEventData(
                    source="veeam",
                    source_type=SourceType.BACKUP,
                    provider="veeam",
                    event_type=event_type,
                    raw_data={
                        "endpoint": endpoint,
                        "records": records,
                        "total": len(records),
                    },
                    observed_at=datetime.now(timezone.utc),
                ))
            except Exception as e:
                log.debug("Veeam %s failed: %s", endpoint, e)
                result.errors.append(f"{event_type}: {e}")

        result.complete()
        return result

    # -- Auth helpers --

    def _acquire_token(self) -> str:
        """Acquire access token via OAuth2 password grant."""
        try:
            import httpx

            base_url = self._get_base_url()
            token_url = f"{base_url}/api/oauth2/token"
            resp = httpx.post(
                token_url,
                data={
                    "grant_type": "password",
                    "username": self._get_username(),
                    "password": self._get_password(),
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json()["access_token"]
        except Exception as e:
            log.error("Veeam token acquisition error: %s", e)
            return ""

    def _get_base_url(self) -> str:
        url = self.config.settings.get("base_url", "") or self.get_secret(
            "WLK_VEEAM_BASE_URL"
        )
        return url.rstrip("/") if url else ""

    def _get_username(self) -> str:
        return self.config.settings.get("username", "") or self.get_secret(
            "WLK_VEEAM_USERNAME"
        )

    def _get_password(self) -> str:
        return self.config.settings.get("password", "") or self.get_secret(
            "WLK_VEEAM_PASSWORD"
        )

    def _auth_headers(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}", "Accept": "application/json"}


# Register
registry.register("veeam", VeeamConnector)
