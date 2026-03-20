"""MLflow connector — Layer 1 implementation for ML/AI model tracking.

Collects registered models, experiments, and model versions from the
MLflow REST API. Supports optional Bearer token authentication.
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

# (endpoint, event_type, response_key)
MLFLOW_ENDPOINTS: list[tuple[str, str, str]] = [
    ("/api/2.0/mlflow/registered-models/list", "mlflow_registered_models", "registered_models"),
    ("/api/2.0/mlflow/experiments/search", "mlflow_experiments", "experiments"),
    ("/api/2.0/mlflow/model-versions/search", "mlflow_model_versions", "model_versions"),
]


class MLflowConnector(BaseConnector):
    """Collects AI/ML model governance telemetry from MLflow Tracking API."""

    def validate(self) -> list[str]:
        errors = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed. Install with: pip install warlock[mlflow]")
        if not self.get_secret("WLK_MLFLOW_TRACKING_URI"):
            errors.append("WLK_MLFLOW_TRACKING_URI env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            base_url = self.get_secret("WLK_MLFLOW_TRACKING_URI").rstrip("/")
            headers = self._headers()
            resp = httpx.get(
                f"{base_url}/api/2.0/mlflow/experiments/search",
                params={"max_results": "1"},
                headers=headers,
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="mlflow",
            source_type=SourceType.CUSTOM,
            provider="mlflow",
        )

        base_url = self.get_secret("WLK_MLFLOW_TRACKING_URI").rstrip("/")
        headers = self._headers()

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, response_key in MLFLOW_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint, response_key)
                    result.events.append(
                        RawEventData(
                            source="mlflow",
                            source_type=SourceType.CUSTOM,
                            provider="mlflow",
                            event_type=event_type,
                            raw_data={
                                "endpoint": endpoint,
                                "response": data,
                            },
                            observed_at=datetime.now(timezone.utc),
                        )
                    )
                except Exception as e:
                    log.debug("MLflow %s failed: %s", endpoint, e)
                    result.errors.append(f"{event_type}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _paginate(self, client, endpoint: str, response_key: str) -> list:
        """Paginate MLflow API using page_token."""
        all_items: list = []
        params: dict[str, str] = {}

        while True:
            resp = client.get(endpoint, params=params)
            resp.raise_for_status()
            body = resp.json()

            items = body.get(response_key, [])
            all_items.extend(items)

            next_token = body.get("next_page_token")
            if not next_token:
                break
            params["page_token"] = next_token

        return all_items

    def _headers(self) -> dict[str, str]:
        headers: dict[str, str] = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        token = self.get_secret("WLK_MLFLOW_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers


# Register
registry.register("mlflow", MLflowConnector)
