"""Vertex AI connector — Layer 1 implementation for AI_ML.

Collects models, endpoints, and datasets from the Vertex AI REST API.
Authenticates with a GCP access token (Bearer).
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

VERTEX_AI_BASE_URL = "https://us-central1-aiplatform.googleapis.com"


class VertexAIConnector(BaseConnector):
    """Collects compliance telemetry from Vertex AI REST API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("GCP_ACCESS_TOKEN"):
            errors.append("GCP_ACCESS_TOKEN env var is not set")
        if not self.config.settings.get("project_id"):
            errors.append("project_id must be set in connector settings")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("GCP_ACCESS_TOKEN")
            project_id = self.config.settings.get("project_id", "")
            location = self.config.settings.get("location", "us-central1")
            base_url = self.config.settings.get("base_url", VERTEX_AI_BASE_URL)
            url = f"{base_url}/v1/projects/{project_id}/locations/{location}/models"
            resp = httpx.get(
                url,
                headers=self._headers(token),
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code in (200, 401, 403)
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="vertex_ai",
            source_type=SourceType.AI_ML,
            provider="vertex_ai",
        )

        token = self.get_secret("GCP_ACCESS_TOKEN")
        project_id = self.config.settings.get("project_id", "")
        location = self.config.settings.get("location", "us-central1")
        base_url = self.config.settings.get("base_url", VERTEX_AI_BASE_URL)
        headers = self._headers(token)

        endpoints: list[tuple[str, str]] = [
            (
                f"{base_url}/v1/projects/{project_id}/locations/{location}/models",
                "vertex_ai_models",
            ),
            (
                f"{base_url}/v1/projects/{project_id}/locations/{location}/endpoints",
                "vertex_ai_endpoints",
            ),
            (
                f"{base_url}/v1/projects/{project_id}/locations/{location}/datasets",
                "vertex_ai_datasets",
            ),
        ]

        client = httpx.Client(headers=headers, timeout=self.config.timeout_seconds)

        try:
            for url, event_type in endpoints:
                try:
                    resp = client.get(url)
                    resp.raise_for_status()
                    body = resp.json()
                    # Vertex AI uses the resource type name as the key
                    key = event_type.replace("vertex_ai_", "")
                    items = body.get(key, body.get("nextPageToken", body))
                    if not isinstance(items, list):
                        items = []
                    result.events.append(
                        RawEventData(
                            source="vertex_ai",
                            source_type=SourceType.AI_ML,
                            provider="vertex_ai",
                            event_type=event_type,
                            raw_data={
                                "url": url,
                                "project_id": project_id,
                                "location": location,
                                "response": items,
                            },
                            observed_at=datetime.now(timezone.utc),
                        )
                    )
                except Exception as e:
                    log.debug("Vertex AI %s failed: %s", url, e)
                    result.errors.append(f"{url}: {e}")
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
registry.register("vertex_ai", VertexAIConnector)
