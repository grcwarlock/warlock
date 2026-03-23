"""CrowdStrike Spotlight connector — collects vulnerability and remediation data."""

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

CROWDSTRIKE_BASE_URL = "https://api.crowdstrike.com"

CROWDSTRIKE_SPOTLIGHT_ENDPOINTS: list[tuple[str, str, dict]] = [
    (
        "/spotlight/combined/vulnerabilities/v1",
        "crowdstrike_spotlight_vulnerabilities",
        {"limit": "400", "filter": "status:'open'"},
    ),
    (
        "/spotlight/queries/remediations/v1",
        "crowdstrike_spotlight_remediations",
        {"limit": "400"},
    ),
]


class CrowdStrikeSpotlightConnector(BaseConnector):
    """Collects Spotlight vulnerability findings from CrowdStrike via OAuth2."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("CROWDSTRIKE_CLIENT_ID"):
            errors.append("CROWDSTRIKE_CLIENT_ID env var is not set")
        if not self.get_secret("CROWDSTRIKE_CLIENT_SECRET"):
            errors.append("CROWDSTRIKE_CLIENT_SECRET env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            token = self._get_oauth_token()
            return bool(token)
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="crowdstrike_spotlight",
            source_type=SourceType.SCANNER,
            provider="crowdstrike_spotlight",
        )

        try:
            import httpx

            token = self._get_oauth_token()
            base_url = self.config.settings.get("base_url", CROWDSTRIKE_BASE_URL)
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
                for endpoint, event_type, params in CROWDSTRIKE_SPOTLIGHT_ENDPOINTS:
                    try:
                        data = self._paginate(client, endpoint, params, event_type)
                        result.events.append(
                            RawEventData(
                                source="crowdstrike_spotlight",
                                source_type=SourceType.SCANNER,
                                provider="crowdstrike_spotlight",
                                event_type=event_type,
                                raw_data={
                                    "endpoint": endpoint,
                                    "base_url": base_url,
                                    "response": data,
                                },
                                observed_at=datetime.now(timezone.utc),
                            )
                        )
                    except Exception as e:
                        log.debug("CrowdStrike Spotlight %s failed: %s", endpoint, e)
                        result.errors.append(f"{endpoint}: {e}")
            finally:
                client.close()

        except Exception as e:
            result.errors.append(f"auth: {e}")

        result.complete()
        return result

    def _get_oauth_token(self) -> str:
        """Exchange client credentials for a bearer token."""
        import httpx

        client_id = self.get_secret("CROWDSTRIKE_CLIENT_ID")
        client_secret = self.get_secret("CROWDSTRIKE_CLIENT_SECRET")
        base_url = self.config.settings.get("base_url", CROWDSTRIKE_BASE_URL)

        resp = httpx.post(
            f"{base_url}/oauth2/token",
            data={"client_id": client_id, "client_secret": client_secret},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=self.config.timeout_seconds,
        )
        resp.raise_for_status()
        return resp.json().get("access_token", "")

    def _paginate(self, client: object, endpoint: str, params: dict, event_type: str) -> list:
        """Paginate CrowdStrike cursor-based responses."""
        all_items: list = []
        current_params = dict(params)

        while True:
            resp = client.get(endpoint, params=current_params)  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()

            # Combined endpoint returns resources directly; queries endpoint returns ids
            resources = body.get("resources") or []
            all_items.extend(resources)

            meta = body.get("meta", {})
            pagination = meta.get("pagination", {}) if isinstance(meta, dict) else {}
            next_after = pagination.get("after") or pagination.get("next_cursor")
            if not next_after or not resources:
                break
            current_params["after"] = next_after

        return all_items


registry.register("crowdstrike_spotlight", CrowdStrikeSpotlightConnector)
