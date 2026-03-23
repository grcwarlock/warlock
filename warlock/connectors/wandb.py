"""Weights & Biases connector — Layer 1 implementation for AI_ML.

Collects projects, runs, and artifacts from the W&B REST API.
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

WANDB_BASE_URL = "https://api.wandb.ai"

WANDB_ENDPOINTS: list[tuple[str, str]] = [
    ("/api/v1/projects", "wandb_projects"),
    ("/api/v1/runs", "wandb_runs"),
    ("/api/v1/artifacts", "wandb_artifacts"),
]


class WandbConnector(BaseConnector):
    """Collects compliance telemetry from Weights & Biases REST API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("WANDB_API_KEY"):
            errors.append("WANDB_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("WANDB_API_KEY")
            base_url = self.config.settings.get("base_url", WANDB_BASE_URL)
            resp = httpx.get(
                f"{base_url}/api/v1/projects",
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
            source="wandb",
            source_type=SourceType.AI_ML,
            provider="wandb",
        )

        token = self.get_secret("WANDB_API_KEY")
        base_url = self.config.settings.get("base_url", WANDB_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type in WANDB_ENDPOINTS:
                try:
                    resp = client.get(endpoint)
                    resp.raise_for_status()
                    data = resp.json()
                    result.events.append(
                        RawEventData(
                            source="wandb",
                            source_type=SourceType.AI_ML,
                            provider="wandb",
                            event_type=event_type,
                            raw_data={
                                "endpoint": endpoint,
                                "base_url": base_url,
                                "response": data if isinstance(data, list) else data.get("results", data.get("data", [])),
                            },
                            observed_at=datetime.now(timezone.utc),
                        )
                    )
                except Exception as e:
                    log.debug("W&B %s failed: %s", endpoint, e)
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
registry.register("wandb", WandbConnector)
