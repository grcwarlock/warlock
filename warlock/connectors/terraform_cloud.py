"""Terraform Cloud connector — Layer 1 implementation for IaC drift & policy.

Collects workspaces (drift status, VCS connection), runs (plan/apply history),
policy checks (Sentinel), and state versions via the Terraform Cloud API v2.
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

_BASE_URL = "https://app.terraform.io/api/v2"


class TerraformCloudConnector(BaseConnector):
    """Collects compliance telemetry from Terraform Cloud API v2."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[terraform_cloud]")
        if not self.get_secret("WLK_TFC_TOKEN"):
            errors.append("WLK_TFC_TOKEN not set")
        if not self.get_secret("WLK_TFC_ORG"):
            errors.append("WLK_TFC_ORG not set")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client()
            org = self.get_secret("WLK_TFC_ORG")
            resp = client.get(f"{_BASE_URL}/organizations/{org}")
            return resp.status_code == 200
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="terraform_cloud",
            source_type=SourceType.INFRASTRUCTURE,
            provider="hashicorp",
        )

        client = self._client()
        org = self.get_secret("WLK_TFC_ORG")

        self._collect_workspaces(client, org, result)
        self._collect_runs(client, org, result)
        self._collect_policy_checks(client, org, result)
        self._collect_state_versions(client, org, result)

        result.complete()
        return result

    # -- HTTP client --

    def _client(self) -> httpx.Client:
        token = self.get_secret("WLK_TFC_TOKEN")
        return httpx.Client(
            timeout=self.config.timeout_seconds,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/vnd.api+json",
            },
        )

    # -- Event helpers --

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="terraform_cloud",
            source_type=SourceType.INFRASTRUCTURE,
            provider="hashicorp",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_workspaces(self, client: httpx.Client, org: str, result: ConnectorResult) -> None:
        """Collect workspaces with drift status and VCS connection info."""
        try:
            resp = client.get(
                f"{_BASE_URL}/organizations/{org}/workspaces",
                params={"page[size]": "100"},
            )
            resp.raise_for_status()
            workspaces = resp.json().get("data", [])
            result.events.append(self._raw_event("tfc_workspaces", {"workspaces": workspaces}))
        except Exception as e:
            log.debug("TFC workspaces collection failed: %s", e)
            result.errors.append(f"tfc_workspaces: {e}")

    def _collect_runs(self, client: httpx.Client, org: str, result: ConnectorResult) -> None:
        """Collect recent runs (plan/apply history) across workspaces."""
        try:
            resp = client.get(
                f"{_BASE_URL}/organizations/{org}/runs",
                params={"page[size]": "100"},
            )
            resp.raise_for_status()
            runs = resp.json().get("data", [])
            result.events.append(self._raw_event("tfc_runs", {"runs": runs}))
        except Exception as e:
            log.debug("TFC runs collection failed: %s", e)
            result.errors.append(f"tfc_runs: {e}")

    def _collect_policy_checks(
        self, client: httpx.Client, org: str, result: ConnectorResult
    ) -> None:
        """Collect Sentinel policy check results from recent runs."""
        try:
            # First get recent runs, then fetch their policy checks
            resp = client.get(
                f"{_BASE_URL}/organizations/{org}/runs",
                params={"page[size]": "50"},
            )
            resp.raise_for_status()
            runs = resp.json().get("data", [])

            policy_checks = []
            for run in runs[:20]:
                run_id = run.get("id", "")
                try:
                    pc_resp = client.get(f"{_BASE_URL}/runs/{run_id}/policy-checks")
                    pc_resp.raise_for_status()
                    checks = pc_resp.json().get("data", [])
                    for check in checks:
                        check["_run_id"] = run_id
                        check["_workspace"] = (
                            run.get("relationships", {})
                            .get("workspace", {})
                            .get("data", {})
                            .get("id", "")
                        )
                    policy_checks.extend(checks)
                except Exception:
                    pass  # Individual run policy check failures are non-fatal

            result.events.append(
                self._raw_event("tfc_policy_checks", {"policy_checks": policy_checks})
            )
        except Exception as e:
            log.debug("TFC policy checks collection failed: %s", e)
            result.errors.append(f"tfc_policy_checks: {e}")

    def _collect_state_versions(
        self, client: httpx.Client, org: str, result: ConnectorResult
    ) -> None:
        """Collect state versions across workspaces."""
        try:
            resp = client.get(
                f"{_BASE_URL}/organizations/{org}/workspaces",
                params={"page[size]": "100"},
            )
            resp.raise_for_status()
            workspaces = resp.json().get("data", [])

            state_versions = []
            for ws in workspaces[:30]:
                ws_id = ws.get("id", "")
                ws_name = ws.get("attributes", {}).get("name", "")
                try:
                    sv_resp = client.get(
                        f"{_BASE_URL}/workspaces/{ws_id}/state-versions",
                        params={"page[size]": "5"},
                    )
                    sv_resp.raise_for_status()
                    versions = sv_resp.json().get("data", [])
                    for v in versions:
                        v["_workspace_id"] = ws_id
                        v["_workspace_name"] = ws_name
                    state_versions.extend(versions)
                except Exception:
                    pass  # Individual workspace failures are non-fatal

            result.events.append(
                self._raw_event("tfc_state_versions", {"state_versions": state_versions})
            )
        except Exception as e:
            log.debug("TFC state versions collection failed: %s", e)
            result.errors.append(f"tfc_state_versions: {e}")


# Register
registry.register("terraform_cloud", TerraformCloudConnector)
