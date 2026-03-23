"""Mimecast connector — Layer 1 implementation for EMAIL_SECURITY.

Collects URL threat logs, attachment threat logs, and audit events
from the Mimecast REST API using HMAC-authenticated requests.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import uuid
from datetime import datetime, timezone

from warlock.connectors.base import (
    BaseConnector,
    ConnectorResult,
    RawEventData,
    SourceType,
    registry,
)

log = logging.getLogger(__name__)

MIMECAST_BASE_URL = "https://api.services.mimecast.com"

MIMECAST_ENDPOINTS: list[tuple[str, str]] = [
    ("/api/ttp/url/get-logs", "mimecast_url_logs"),
    ("/api/ttp/attachment/get-logs", "mimecast_attachment_logs"),
    ("/api/audit/get-audit-events", "mimecast_audit_events"),
]


class MimecastConnector(BaseConnector):
    """Collects compliance telemetry from Mimecast REST API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("MIMECAST_ACCESS_KEY"):
            errors.append("MIMECAST_ACCESS_KEY env var is not set")
        if not self.get_secret("MIMECAST_SECRET_KEY"):
            errors.append("MIMECAST_SECRET_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            base_url = self.config.settings.get("base_url", MIMECAST_BASE_URL)
            headers, _ = self._auth_headers("/api/audit/get-audit-events")
            resp = httpx.post(
                f"{base_url}/api/audit/get-audit-events",
                headers=headers,
                json={"meta": {"pagination": {"pageSize": 1}}},
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code in (200, 400, 401)
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="mimecast",
            source_type=SourceType.EMAIL_SECURITY,
            provider="mimecast",
        )

        base_url = self.config.settings.get("base_url", MIMECAST_BASE_URL)
        client = httpx.Client(timeout=self.config.timeout_seconds)

        try:
            for endpoint, event_type in MIMECAST_ENDPOINTS:
                try:
                    headers, request_id = self._auth_headers(endpoint)
                    resp = client.post(
                        f"{base_url}{endpoint}",
                        headers=headers,
                        json={"meta": {"pagination": {"pageSize": 500}}},
                    )
                    resp.raise_for_status()
                    body = resp.json()
                    # Mimecast wraps results in data array
                    items = body.get("data", [])
                    if isinstance(items, list) and len(items) > 0 and isinstance(items[0], list):
                        items = items[0]
                    result.events.append(
                        RawEventData(
                            source="mimecast",
                            source_type=SourceType.EMAIL_SECURITY,
                            provider="mimecast",
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
                    log.debug("Mimecast %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _auth_headers(self, uri: str) -> tuple[dict[str, str], str]:
        """Build Mimecast HMAC-SHA1 authentication headers."""
        access_key = self.get_secret("MIMECAST_ACCESS_KEY")
        secret_key = self.get_secret("MIMECAST_SECRET_KEY")
        request_id = str(uuid.uuid4())
        date_str = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S UTC")

        # HMAC-SHA1 signature over "date:request-id:uri:app-key"
        app_key = self.config.settings.get("app_key", "warlock-grc")
        hmac_msg = f"{date_str}:{request_id}:{uri}:{app_key}"
        secret_bytes = base64.b64decode(secret_key) if secret_key else b""
        signature = base64.b64encode(
            hmac.new(secret_bytes, hmac_msg.encode(), hashlib.sha1).digest()
        ).decode()

        auth_header = f"MC {access_key}:MCS+HMAC-SHA1:{request_id}:{signature}"

        headers = {
            "Authorization": auth_header,
            "x-mc-req-id": request_id,
            "x-mc-date": date_str,
            "x-mc-app-id": app_key,
            "Content-Type": "application/json",
        }
        return headers, request_id


# Register
registry.register("mimecast", MimecastConnector)
