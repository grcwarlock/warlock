"""Kubernetes connector — Layer 1 implementation for container security.

Collects namespaces, network policies, RBAC bindings, admission controls,
running pods, and deployments from the Kubernetes API server.
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

K8S_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/api/v1/namespaces", "k8s_namespaces", {}),
    ("/apis/networking.k8s.io/v1/networkpolicies", "k8s_network_policies", {}),
    ("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", "k8s_rbac_bindings", {}),
    (
        "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations",
        "k8s_admission_controls",
        {},
    ),
    ("/api/v1/pods", "k8s_running_pods", {"fieldSelector": "status.phase!=Succeeded"}),
    ("/apis/apps/v1/deployments", "k8s_deployments", {}),
]


class KubernetesConnector(BaseConnector):
    """Collects security telemetry from the Kubernetes API server."""

    def validate(self) -> list[str]:
        errors = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed. Install with: pip install warlock[kubernetes]")
        if not self.get_secret("WLK_K8S_API_URL"):
            errors.append("WLK_K8S_API_URL env var is not set")
        if not self.get_secret("WLK_K8S_TOKEN"):
            errors.append("WLK_K8S_TOKEN env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            api_url = self.get_secret("WLK_K8S_API_URL").rstrip("/")
            token = self.get_secret("WLK_K8S_TOKEN")
            resp = httpx.get(
                f"{api_url}/api/v1",
                headers=self._headers(token),
                verify=self._get_verify(),
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
            source="kubernetes",
            source_type=SourceType.CLOUD,
            provider="kubernetes",
        )

        api_url = self.get_secret("WLK_K8S_API_URL").rstrip("/")
        token = self.get_secret("WLK_K8S_TOKEN")
        headers = self._headers(token)

        client = httpx.Client(
            base_url=api_url,
            headers=headers,
            verify=self._get_verify(),
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, params in K8S_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint, params)
                    result.events.append(
                        RawEventData(
                            source="kubernetes",
                            source_type=SourceType.CLOUD,
                            provider="kubernetes",
                            event_type=event_type,
                            raw_data={
                                "endpoint": endpoint,
                                "api_url": api_url,
                                "response": data,
                            },
                            observed_at=datetime.now(timezone.utc),
                        )
                    )
                except Exception as e:
                    log.debug("Kubernetes %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }

    def _get_verify(self):
        """Return CA cert path if configured, else True for default verification."""
        import os

        ca_cert = os.environ.get("WLK_K8S_CA_CERT", "")
        return ca_cert if ca_cert else True

    def _paginate(self, client, endpoint: str, params: dict) -> list:
        """Follow Kubernetes list pagination via continue token."""
        all_items: list = []
        current_params = dict(params)

        while True:
            resp = client.get(endpoint, params=current_params)
            resp.raise_for_status()
            body = resp.json()

            items = body.get("items", [])
            all_items.extend(items)

            continue_token = body.get("metadata", {}).get("continue", "")
            if not continue_token:
                break
            current_params["continue"] = continue_token

        return all_items


# Register
registry.register("kubernetes", KubernetesConnector)
