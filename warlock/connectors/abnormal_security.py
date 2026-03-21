"""Abnormal Security connector — Layer 1 implementation for email security.

Collects threats (BEC, phishing, malware), cases, and abuse mailbox
submissions via Abnormal Security REST API.
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

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]

BASE_URL = "https://api.abnormalplatform.com/v1"


class AbnormalSecurityConnector(BaseConnector):
    """Collects compliance telemetry from Abnormal Security REST API."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[abnormal]")
        if not self.get_secret("WLK_ABNORMAL_API_TOKEN"):
            errors.append("WLK_ABNORMAL_API_TOKEN not set")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client()
            resp = client.get(f"{BASE_URL}/threats", params={"pageSize": 1})
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="abnormal_security",
            source_type=SourceType.EMAIL,
            provider="abnormal_security",
        )

        client = self._client()

        self._collect_threats(client, result)
        self._collect_cases(client, result)
        self._collect_abuse_mailbox(client, result)

        result.complete()
        return result

    # -- Auth & Client --

    def _client(self) -> httpx.Client:
        """Build an httpx client with Bearer token auth."""
        token = self.get_secret("WLK_ABNORMAL_API_TOKEN")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        }
        return httpx.Client(headers=headers, timeout=self.config.timeout_seconds)

    # -- Pagination --

    def _paginate(
        self,
        client: httpx.Client,
        url: str,
        result_key: str = "results",
    ) -> list:
        """Cursor-based pagination for Abnormal Security API."""
        max_pages = self.config.settings.get("max_pages", 20)
        per_page = self.config.settings.get("per_page", 100)
        all_items: list = []
        params: dict = {"pageSize": per_page}

        for _ in range(max_pages):
            resp = client.get(url, params=params)
            resp.raise_for_status()
            body = resp.json()

            items = body.get(result_key, [])
            if isinstance(items, list):
                all_items.extend(items)
            else:
                return [items] if items else []

            next_page = body.get("nextPageNumber")
            if not next_page:
                break
            params["pageNumber"] = next_page

        return all_items

    # -- Event helpers --

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="abnormal_security",
            source_type=SourceType.EMAIL,
            provider="abnormal_security",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_threats(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect email threats (BEC, phishing, malware)."""
        try:
            url = f"{BASE_URL}/threats"
            threats = self._paginate(client, url, result_key="threats")
            result.events.append(
                self._raw_event(
                    "abnormal_threats",
                    {"threats": threats},
                )
            )
        except Exception as e:
            log.debug("Abnormal Security threats collection failed: %s", e)
            result.errors.append(f"abnormal_threats: {e}")

    def _collect_cases(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect investigation cases."""
        try:
            url = f"{BASE_URL}/cases"
            cases = self._paginate(client, url, result_key="cases")
            result.events.append(
                self._raw_event(
                    "abnormal_cases",
                    {"cases": cases},
                )
            )
        except Exception as e:
            log.debug("Abnormal Security cases collection failed: %s", e)
            result.errors.append(f"abnormal_cases: {e}")

    def _collect_abuse_mailbox(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect abuse mailbox submissions."""
        try:
            url = f"{BASE_URL}/abusemailbox"
            submissions = self._paginate(client, url, result_key="results")
            result.events.append(
                self._raw_event(
                    "abnormal_abuse_mailbox",
                    {"submissions": submissions},
                )
            )
        except Exception as e:
            log.debug("Abnormal Security abuse mailbox collection failed: %s", e)
            result.errors.append(f"abnormal_abuse_mailbox: {e}")


# Register
registry.register("abnormal_security", AbnormalSecurityConnector)
