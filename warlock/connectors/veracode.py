"""Veracode connector — Layer 1 implementation for SAST / DAST / SCA.

Collects applications, findings, policy compliance, and SCA results
via the Veracode REST API with HMAC auth (API ID + API Key).
"""

from __future__ import annotations

import hashlib
import hmac
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


class VeracodeConnector(BaseConnector):
    """Collects compliance telemetry from Veracode REST API."""

    BASE_URL = "https://api.veracode.com/appsec/v2"

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[veracode]")
        if not self.get_secret("WLK_VERACODE_API_ID"):
            errors.append("WLK_VERACODE_API_ID not set")
        if not self.get_secret("WLK_VERACODE_API_KEY"):
            errors.append("WLK_VERACODE_API_KEY not set")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client()
            resp = client.get(f"{self.BASE_URL}/applications", params={"size": 1})
            return resp.status_code == 200
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="veracode",
            source_type=SourceType.CODE,
            provider="veracode",
        )

        client = self._client()

        self._collect_applications(client, result)
        self._collect_findings(client, result)
        self._collect_policy(client, result)
        self._collect_sca(client, result)

        result.complete()
        return result

    # -- Client helper --

    def _client(self) -> httpx.Client:
        """Build an httpx client with Veracode HMAC auth headers."""
        api_id = self.get_secret("WLK_VERACODE_API_ID")
        api_key = self.get_secret("WLK_VERACODE_API_KEY")

        # Veracode HMAC signing
        nonce = hashlib.sha256(datetime.now(timezone.utc).isoformat().encode()).hexdigest()[:32]
        timestamp = str(int(datetime.now(timezone.utc).timestamp() * 1000))

        signing_data = f"id={api_id}&host=api.veracode.com&url=/appsec/v2/&method=GET"
        signature = hmac.new(
            api_key.encode("utf-8"),
            signing_data.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        auth_header = (
            f"VERACODE-HMAC-SHA-256 id={api_id},ts={timestamp},nonce={nonce},sig={signature}"
        )

        return httpx.Client(
            headers={
                "Authorization": auth_header,
                "Accept": "application/json",
            },
            timeout=self.config.timeout_seconds,
        )

    # -- Event helper --

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="veracode",
            source_type=SourceType.CODE,
            provider="veracode",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_applications(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect Veracode application profiles."""
        try:
            resp = client.get(
                f"{self.BASE_URL}/applications",
                params={"size": 500},
            )
            resp.raise_for_status()
            body = resp.json()
            apps = body.get("_embedded", {}).get("applications", [])
            result.events.append(self._raw_event("veracode_applications", {"applications": apps}))
        except Exception as e:
            log.debug("Veracode applications collection failed: %s", e)
            result.errors.append(f"veracode_applications: {e}")

    def _collect_findings(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect static and dynamic analysis findings."""
        try:
            resp = client.get(
                f"{self.BASE_URL}/findings",
                params={"size": 500, "include_annot": "true"},
            )
            resp.raise_for_status()
            body = resp.json()
            findings = body.get("_embedded", {}).get("findings", [])
            result.events.append(self._raw_event("veracode_findings", {"findings": findings}))
        except Exception as e:
            log.debug("Veracode findings collection failed: %s", e)
            result.errors.append(f"veracode_findings: {e}")

    def _collect_policy(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect policy compliance status for applications."""
        try:
            resp = client.get(
                f"{self.BASE_URL}/applications",
                params={"size": 500},
            )
            resp.raise_for_status()
            body = resp.json()
            apps = body.get("_embedded", {}).get("applications", [])
            # Extract policy compliance from each application profile
            policy_results = []
            for app in apps:
                profile = app.get("profile", {})
                policy_results.append(
                    {
                        "app_guid": app.get("guid", ""),
                        "app_name": profile.get("name", ""),
                        "policy_name": profile.get("policies", [{}])[0].get("name", "")
                        if profile.get("policies")
                        else "",
                        "policy_compliance_status": app.get("policy_compliance_status", ""),
                        "last_completed_scan_date": app.get("last_completed_scan_date", ""),
                    }
                )
            result.events.append(
                self._raw_event("veracode_policy", {"policy_results": policy_results})
            )
        except Exception as e:
            log.debug("Veracode policy collection failed: %s", e)
            result.errors.append(f"veracode_policy: {e}")

    def _collect_sca(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect Software Composition Analysis results."""
        try:
            resp = client.get(
                "https://api.veracode.com/srcclr/v3/workspaces",
                params={"size": 500},
            )
            resp.raise_for_status()
            body = resp.json()
            workspaces = body.get("_embedded", {}).get("workspaces", [])

            sca_results = []
            for ws in workspaces:
                ws_id = ws.get("id", "")
                ws_name = ws.get("name", "")
                try:
                    issues_resp = client.get(
                        f"https://api.veracode.com/srcclr/v3/workspaces/{ws_id}/issues",
                        params={"size": 100},
                    )
                    issues_resp.raise_for_status()
                    issues_body = issues_resp.json()
                    issues = issues_body.get("_embedded", {}).get("issues", [])
                    sca_results.append(
                        {
                            "workspace_id": ws_id,
                            "workspace_name": ws_name,
                            "issues": issues,
                        }
                    )
                except Exception:
                    log.debug("Veracode SCA issues for workspace %s failed", ws_id)

            result.events.append(self._raw_event("veracode_sca", {"sca_results": sca_results}))
        except Exception as e:
            log.debug("Veracode SCA collection failed: %s", e)
            result.errors.append(f"veracode_sca: {e}")


# Register
registry.register("veracode", VeracodeConnector)
