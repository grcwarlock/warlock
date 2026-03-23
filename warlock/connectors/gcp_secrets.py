"""GCP Secret Manager connector — Layer 1 implementation for CLOUD.

Collects secret metadata from Google Cloud Secret Manager using Bearer token
authentication. Secret values are never collected.
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

GCP_SECRETS_BASE_URL = "https://secretmanager.googleapis.com"


class GcpSecretsConnector(BaseConnector):
    """Collects secret metadata from GCP Secret Manager REST API.

    Security note: Only secret metadata is collected (name, labels, replication,
    create time, rotation schedule). Secret payloads are never accessed.
    """

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("GCP_ACCESS_TOKEN"):
            errors.append("GCP_ACCESS_TOKEN env var is not set")
        if not self.config.settings.get("project_id"):
            errors.append("settings.project_id is required")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("GCP_ACCESS_TOKEN")
            project_id = self.config.settings.get("project_id", "")
            base_url = self.config.settings.get("base_url", GCP_SECRETS_BASE_URL)
            resp = httpx.get(
                f"{base_url}/v1/projects/{project_id}/secrets",
                headers=self._headers(token),
                params={"pageSize": "1"},
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code == 200
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="gcp_secrets",
            source_type=SourceType.CLOUD,
            provider="gcp_secrets",
        )

        token = self.get_secret("GCP_ACCESS_TOKEN")
        project_id = self.config.settings.get("project_id", "")
        base_url = self.config.settings.get("base_url", GCP_SECRETS_BASE_URL)

        if not project_id:
            result.errors.append("settings.project_id is not configured")
            result.complete("error")
            return result

        try:
            secrets = self._list_secrets(token, project_id, base_url)
            result.events.append(
                RawEventData(
                    source="gcp_secrets",
                    source_type=SourceType.CLOUD,
                    provider="gcp_secrets",
                    event_type="gcp_secrets_metadata",
                    raw_data={
                        "project_id": project_id,
                        "response": secrets,
                    },
                    observed_at=datetime.now(timezone.utc),
                )
            )
        except Exception as e:
            log.debug("GCP Secret Manager collection failed: %s", e)
            result.errors.append(str(e))

        result.complete()
        return result

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

    def _list_secrets(self, token: str, project_id: str, base_url: str) -> list[dict]:
        """List all secret metadata from GCP Secret Manager. Values are never fetched."""
        import httpx

        all_secrets: list[dict] = []
        page_token: str | None = None
        endpoint = f"{base_url}/v1/projects/{project_id}/secrets"

        client = httpx.Client(
            headers=self._headers(token),
            timeout=self.config.timeout_seconds,
        )

        try:
            while True:
                params: dict = {"pageSize": "100"}
                if page_token:
                    params["pageToken"] = page_token

                resp = client.get(endpoint, params=params)
                resp.raise_for_status()
                body = resp.json()

                secrets = body.get("secrets", [])
                all_secrets.extend(secrets)

                page_token = body.get("nextPageToken")
                if not page_token or not secrets:
                    break
        finally:
            client.close()

        return all_secrets


# Register
registry.register("gcp_secrets", GcpSecretsConnector)
