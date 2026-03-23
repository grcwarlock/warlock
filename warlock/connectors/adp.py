"""ADP connector — Layer 1 implementation for HRIS.

Collects worker records and work assignments via ADP HR API v2.
Uses OAuth2 client credentials authentication.
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

ADP_BASE_URL = "https://api.adp.com"
ADP_TOKEN_URL = "https://accounts.adp.com/auth/oauth/v2/token"


class ADPConnector(BaseConnector):
    """Collects compliance telemetry from ADP HR APIs."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("ADP_CLIENT_ID"):
            errors.append("ADP_CLIENT_ID env var is not set")
        if not self.get_secret("ADP_CLIENT_SECRET"):
            errors.append("ADP_CLIENT_SECRET env var is not set")
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
            source="adp",
            source_type=SourceType.HRIS,
            provider="adp",
        )

        try:
            token = self._get_oauth_token()
        except Exception as e:
            result.errors.append(f"OAuth token fetch failed: {e}")
            result.complete("error")
            return result

        import httpx

        base_url = self.config.settings.get("base_url", ADP_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            # Workers
            try:
                workers = self._paginate(client, "/hr/v2/workers")
                result.events.append(
                    RawEventData(
                        source="adp",
                        source_type=SourceType.HRIS,
                        provider="adp",
                        event_type="adp_workers",
                        raw_data={
                            "endpoint": "/hr/v2/workers",
                            "base_url": base_url,
                            "response": workers,
                        },
                        observed_at=datetime.now(timezone.utc),
                    )
                )
            except Exception as e:
                log.debug("ADP workers failed: %s", e)
                result.errors.append(f"adp_workers: {e}")

            # Work assignments — collected per worker (sampled to avoid N+1)
            # In production, use $filter on workerStatus; here we emit the endpoint pattern
            try:
                resp = client.get("/hr/v2/workers", params={"$top": "1"})
                resp.raise_for_status()
                sample_workers = resp.json().get("workers", [])
                assignments: list = []
                for w in sample_workers[:5]:  # sample up to 5 for demo
                    wid = w.get("associateOID", "")
                    if not wid:
                        continue
                    try:
                        wa_resp = client.get(f"/hr/v2/workers/{wid}/work-assignments")
                        wa_resp.raise_for_status()
                        assignments.extend(wa_resp.json().get("workAssignments", []))
                    except Exception:
                        pass
                result.events.append(
                    RawEventData(
                        source="adp",
                        source_type=SourceType.HRIS,
                        provider="adp",
                        event_type="adp_work_assignments",
                        raw_data={
                            "endpoint": "/hr/v2/workers/{id}/work-assignments",
                            "base_url": base_url,
                            "response": assignments,
                        },
                        observed_at=datetime.now(timezone.utc),
                    )
                )
            except Exception as e:
                log.debug("ADP work assignments failed: %s", e)
                result.errors.append(f"adp_work_assignments: {e}")

        finally:
            client.close()

        result.complete()
        return result

    def _get_oauth_token(self) -> str:
        import httpx

        client_id = self.get_secret("ADP_CLIENT_ID")
        client_secret = self.get_secret("ADP_CLIENT_SECRET")
        token_url = self.config.settings.get("token_url", ADP_TOKEN_URL)

        resp = httpx.post(
            token_url,
            data={"grant_type": "client_credentials"},
            auth=(client_id, client_secret),
            timeout=30,
        )
        resp.raise_for_status()
        return str(resp.json().get("access_token", ""))

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _paginate(self, client: object, endpoint: str) -> list:
        """Follow ADP $skip-based pagination."""
        all_items: list = []
        skip = 0
        top = 100

        # Determine the response key
        _key_map = {
            "/hr/v2/workers": "workers",
        }
        response_key = _key_map.get(endpoint, "value")

        while True:
            resp = client.get(  # type: ignore[attr-defined]
                endpoint, params={"$top": top, "$skip": skip}
            )
            resp.raise_for_status()
            body = resp.json()
            items = body.get(response_key, [])
            all_items.extend(items)

            if len(items) < top:
                break
            skip += top

        return all_items


# Register
registry.register("adp", ADPConnector)
