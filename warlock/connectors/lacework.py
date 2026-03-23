"""Lacework connector — collects alerts, vulnerabilities, and compliance data."""

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

LACEWORK_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/api/v2/Alerts", "lacework_alerts", {"pageSize": "500"}),
    ("/api/v2/Vulnerabilities/Containers", "lacework_vulnerabilities", {"pageSize": "500"}),
    ("/api/v2/Compliance/evaluations", "lacework_compliance", {"pageSize": "500"}),
]


class LaceworkConnector(BaseConnector):
    """Collects CSPM and vulnerability data from Lacework API v2."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("LACEWORK_API_KEY"):
            errors.append("LACEWORK_API_KEY env var is not set")
        if not self.get_secret("LACEWORK_API_SECRET"):
            errors.append("LACEWORK_API_SECRET env var is not set")
        if not self.config.settings.get("account"):
            errors.append("settings.account is required (e.g. mycompany.lacework.net)")
        return errors

    def health_check(self) -> bool:
        try:
            token = self._get_token()
            return bool(token)
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="lacework",
            source_type=SourceType.CSPM,
            provider="lacework",
        )

        try:
            import httpx

            token = self._get_token()
            account = self.config.settings.get("account", "")
            base_url = f"https://{account}"
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }

            client = httpx.Client(
                base_url=base_url,
                headers=headers,
                timeout=self.config.timeout_seconds,
            )

            try:
                for endpoint, event_type, params in LACEWORK_ENDPOINTS:
                    try:
                        data = self._paginate(client, endpoint, params)
                        result.events.append(
                            RawEventData(
                                source="lacework",
                                source_type=SourceType.CSPM,
                                provider="lacework",
                                event_type=event_type,
                                raw_data={
                                    "endpoint": endpoint,
                                    "account": account,
                                    "response": data,
                                },
                                observed_at=datetime.now(timezone.utc),
                            )
                        )
                    except Exception as e:
                        log.debug("Lacework %s failed: %s", endpoint, e)
                        result.errors.append(f"{endpoint}: {e}")
            finally:
                client.close()

        except Exception as e:
            result.errors.append(f"auth: {e}")

        result.complete()
        return result

    def _get_token(self) -> str:
        """Exchange API key+secret for a short-lived bearer token."""
        import httpx

        api_key = self.get_secret("LACEWORK_API_KEY")
        api_secret = self.get_secret("LACEWORK_API_SECRET")
        account = self.config.settings.get("account", "")
        base_url = f"https://{account}"

        resp = httpx.post(
            f"{base_url}/api/v2/access/tokens",
            headers={
                "X-LW-UAKS": api_key,
                "Content-Type": "application/json",
            },
            json={"keyId": api_key, "expiryTime": 3600},
            timeout=self.config.timeout_seconds,
        )
        resp.raise_for_status()
        return resp.json().get("token", "")

    def _paginate(self, client: object, endpoint: str, params: dict) -> list:
        """Paginate Lacework cursor-based responses."""
        all_items: list = []
        current_params = dict(params)

        while True:
            resp = client.get(endpoint, params=current_params)  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()
            items = body.get("data", [])
            all_items.extend(items)
            paging = body.get("paging", {})
            next_cursor = paging.get("urls", {}).get("nextPage") if isinstance(paging, dict) else None
            if not next_cursor or not items:
                break
            current_params["nextPage"] = next_cursor

        return all_items


registry.register("lacework", LaceworkConnector)
