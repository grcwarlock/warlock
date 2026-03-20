"""Elastic Security connector — Layer 1 implementation for SIEM.

Collects security alerts, detection rules, and agent status from the
Elasticsearch REST API via httpx with API key authentication.
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


class ElasticConnector(BaseConnector):
    """Collects compliance telemetry from Elastic Security via REST API."""

    def validate(self) -> list[str]:
        errors = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed. Install with: pip install warlock[elastic]")
        if not self.config.settings.get("base_url"):
            errors.append("Missing required setting: base_url (e.g. https://elastic:9200)")
        if not self.get_secret("ELASTIC_API_KEY"):
            errors.append("Set ELASTIC_API_KEY env var")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            url = f"{self._base_url}/_cluster/health"
            resp = httpx.get(
                url,
                headers=self._auth_headers(),
                verify=self._verify_ssl,
                timeout=30,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="elastic",
            source_type=SourceType.SIEM,
            provider="elastic",
        )

        headers = self._auth_headers()
        kibana_headers = {**headers, "kbn-xsrf": "true"}
        kibana_url = self.config.settings.get("kibana_url", self._base_url)

        checks: list[tuple[str, str, str, dict | None, dict | None]] = [
            # Security alerts — active, critical/high severity
            (
                "POST",
                f"{self._base_url}/.alerts-security.alerts-*/_search",
                "elastic_security_alerts",
                None,
                {
                    "size": 500,
                    "query": {
                        "bool": {
                            "must": [
                                {"terms": {"kibana.alert.severity": ["critical", "high"]}},
                                {"term": {"kibana.alert.workflow_status": "open"}},
                            ]
                        }
                    },
                    "sort": [{"@timestamp": {"order": "desc"}}],
                },
            ),
            # Detection rules
            (
                "GET",
                f"{kibana_url}/api/detection_engine/rules/_find",
                "elastic_detection_rules",
                {"per_page": "1000", "sort_field": "name", "sort_order": "asc"},
                None,
            ),
            # Agent status
            (
                "GET",
                f"{kibana_url}/api/fleet/agent_status",
                "elastic_agent_status",
                None,
                None,
            ),
        ]

        with httpx.Client(timeout=self.config.timeout_seconds, verify=self._verify_ssl) as client:
            for method, url, event_type, params, body in checks:
                try:
                    use_headers = kibana_headers if "/api/" in url else headers
                    if method == "POST":
                        resp = client.post(url, headers=use_headers, json=body)
                    else:
                        resp = client.get(url, headers=use_headers, params=params)
                    resp.raise_for_status()
                    data = resp.json()

                    result.events.append(
                        RawEventData(
                            source="elastic",
                            source_type=SourceType.SIEM,
                            provider="elastic",
                            event_type=event_type,
                            raw_data={
                                "base_url": self._base_url,
                                "response": data,
                            },
                            observed_at=datetime.now(timezone.utc),
                        )
                    )
                except Exception as e:
                    log.debug("Elastic %s failed: %s", event_type, e)
                    result.errors.append(f"{event_type}: {e}")

        result.complete()
        return result

    # -- internal helpers --

    @property
    def _base_url(self) -> str:
        return self.config.settings["base_url"].rstrip("/")

    @property
    def _verify_ssl(self) -> bool:
        return self.config.settings.get("verify_ssl", True)

    def _auth_headers(self) -> dict[str, str]:
        api_key = self.get_secret("ELASTIC_API_KEY")
        return {
            "Authorization": f"ApiKey {api_key}",
            "Content-Type": "application/json",
        }


# Register
registry.register("elastic", ElasticConnector)
