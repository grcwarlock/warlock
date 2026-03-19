"""Okta connector — Layer 1 implementation for IAM.

Collects users, groups, system log events, policies, applications, and factors.
Uses Okta REST API via httpx with API token authentication.
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

# Endpoint → event_type mapping
OKTA_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/api/v1/users", "okta_users", {"limit": "200"}),
    ("/api/v1/groups", "okta_groups", {"limit": "200"}),
    ("/api/v1/logs", "okta_system_log", {
        "limit": "1000",
        "filter": 'eventType eq "user.session.start" or '
                  'eventType eq "user.authentication.auth_via_mfa" or '
                  'eventType eq "user.account.privilege.grant" or '
                  'eventType eq "policy.evaluate_sign_on"',
    }),
    ("/api/v1/policies", "okta_policies", {"type": "PASSWORD"}),
    ("/api/v1/apps", "okta_applications", {"limit": "200"}),
]


class OktaConnector(BaseConnector):
    """Collects compliance telemetry from Okta REST APIs."""

    def validate(self) -> list[str]:
        errors = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed. Install with: pip install warlock[okta]")
        if not self.get_secret("OKTA_API_TOKEN"):
            errors.append("OKTA_API_TOKEN env var is not set")
        if not self.config.settings.get("domain"):
            errors.append("'domain' must be set in connector settings (e.g. 'mycompany.okta.com')")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            domain = self.config.settings["domain"]
            token = self.get_secret("OKTA_API_TOKEN")
            resp = httpx.get(
                f"https://{domain}/api/v1/org",
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
            source="okta",
            source_type=SourceType.IAM,
            provider="okta",
        )

        domain = self.config.settings["domain"]
        token = self.get_secret("OKTA_API_TOKEN")
        base_url = f"https://{domain}"
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, params in OKTA_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint, params)
                    result.events.append(RawEventData(
                        source="okta",
                        source_type=SourceType.IAM,
                        provider="okta",
                        event_type=event_type,
                        raw_data={
                            "endpoint": endpoint,
                            "domain": domain,
                            "response": data,
                        },
                        observed_at=datetime.now(timezone.utc),
                    ))
                except Exception as e:
                    log.debug("Okta %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")

            # Collect enrolled factors per user
            try:
                users = []
                for ev in result.events:
                    if ev.event_type == "okta_users":
                        users = ev.raw_data.get("response", [])
                        break
                factors_data = []
                for user in users[:200]:  # cap to avoid rate limits
                    uid = user.get("id", "")
                    if not uid:
                        continue
                    try:
                        resp = client.get(f"/api/v1/users/{uid}/factors")
                        resp.raise_for_status()
                        factors_data.append({"user_id": uid, "factors": resp.json()})
                    except Exception:
                        pass
                if factors_data:
                    result.events.append(RawEventData(
                        source="okta",
                        source_type=SourceType.IAM,
                        provider="okta",
                        event_type="okta_factors",
                        raw_data={
                            "endpoint": "/api/v1/users/{id}/factors",
                            "domain": domain,
                            "response": factors_data,
                        },
                        observed_at=datetime.now(timezone.utc),
                    ))
            except Exception as e:
                log.debug("Okta factors collection failed: %s", e)
                result.errors.append(f"factors: {e}")

        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"SSWS {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _paginate(self, client, endpoint: str, params: dict) -> list:
        """Follow Okta link-header pagination."""
        all_items: list = []
        url = endpoint
        current_params = dict(params)

        while url:
            resp = client.get(url, params=current_params)
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, list):
                all_items.extend(data)
            else:
                all_items.append(data)

            # Okta pagination via Link header
            url = None
            current_params = {}
            link_header = resp.headers.get("link", "")
            for part in link_header.split(","):
                if 'rel="next"' in part:
                    url = part.split(";")[0].strip().strip("<>")
                    # next URL is absolute, strip base
                    if url.startswith("https://"):
                        from urllib.parse import urlparse
                        parsed = urlparse(url)
                        url = parsed.path + ("?" + parsed.query if parsed.query else "")
                    break

        return all_items


# Register
registry.register("okta", OktaConnector)
