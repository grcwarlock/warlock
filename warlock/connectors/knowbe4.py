"""KnowBe4 connector — Layer 1 implementation for security awareness training.

Collects training campaigns, enrollments, phishing campaigns, phishing results,
and user data. Uses KnowBe4 REST API with API token authentication.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from warlock.connectors.base import (
    BaseConnector,
    ConnectorConfig,
    ConnectorResult,
    RawEventData,
    SourceType,
    registry,
)

log = logging.getLogger(__name__)

# Region → base URL mapping
KNOWBE4_REGIONS: dict[str, str] = {
    "us": "https://us.api.knowbe4.com",
    "eu": "https://eu.api.knowbe4.com",
    "uk": "https://uk.api.knowbe4.com",
    "ca": "https://ca.api.knowbe4.com",
    "de": "https://de.api.knowbe4.com",
}

# Endpoint → event_type mapping
KNOWBE4_ENDPOINTS: list[tuple[str, str]] = [
    ("/v1/training/campaigns", "kb4_training_campaigns"),
    ("/v1/training/enrollments", "kb4_training_enrollments"),
    ("/v1/phishing/campaigns", "kb4_phishing_campaigns"),
    ("/v1/phishing/security_tests", "kb4_phishing_results"),
    ("/v1/users", "kb4_users"),
]


class KnowBe4Connector(BaseConnector):
    """Collects security awareness training telemetry from KnowBe4 REST APIs."""

    def validate(self) -> list[str]:
        errors = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed. Install with: pip install warlock[knowbe4]")
        if not self.get_secret("WLK_KNOWBE4_API_TOKEN"):
            errors.append("WLK_KNOWBE4_API_TOKEN env var is not set")
        region = self.config.settings.get("region", "us")
        if region not in KNOWBE4_REGIONS:
            errors.append(f"'region' must be one of {list(KNOWBE4_REGIONS.keys())}, got '{region}'")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            base_url = self._base_url()
            token = self.get_secret("WLK_KNOWBE4_API_TOKEN")
            resp = httpx.get(
                f"{base_url}/v1/account",
                headers=self._headers(token),
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="knowbe4",
            source_type=SourceType.TRAINING,
            provider="knowbe4",
        )

        base_url = self._base_url()
        token = self.get_secret("WLK_KNOWBE4_API_TOKEN")
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type in KNOWBE4_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint)
                    raw_data: dict = {
                        "endpoint": endpoint,
                        "region": self.config.settings.get("region", "us"),
                        "response": data,
                    }

                    # For phishing results, fetch recipients for each security test
                    if event_type == "kb4_phishing_results" and isinstance(data, list):
                        for test in data:
                            test_id = test.get("pst_id") or test.get("id")
                            if not test_id:
                                continue
                            try:
                                recipients = self._paginate(
                                    client,
                                    f"/v1/phishing/security_tests/{test_id}/recipients",
                                )
                                test["recipients"] = recipients
                            except Exception as e:
                                log.debug(
                                    "KnowBe4 recipients for test %s failed: %s",
                                    test_id, e,
                                )

                    result.events.append(RawEventData(
                        source="knowbe4",
                        source_type=SourceType.TRAINING,
                        provider="knowbe4",
                        event_type=event_type,
                        raw_data=raw_data,
                        observed_at=datetime.now(timezone.utc),
                    ))
                except Exception as e:
                    log.debug("KnowBe4 %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _base_url(self) -> str:
        region = self.config.settings.get("region", "us")
        return KNOWBE4_REGIONS.get(region, KNOWBE4_REGIONS["us"])

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _paginate(self, client, endpoint: str) -> list:
        """Follow KnowBe4 page-based pagination."""
        all_items: list = []
        page = 1
        per_page = 500

        while True:
            resp = client.get(endpoint, params={"page": page, "per_page": per_page})
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, list):
                if not data:
                    break
                all_items.extend(data)
                if len(data) < per_page:
                    break
                page += 1
            else:
                all_items.append(data)
                break

        return all_items


# Register
registry.register("knowbe4", KnowBe4Connector)
