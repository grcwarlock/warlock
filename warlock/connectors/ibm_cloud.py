"""IBM Cloud connector — Layer 1 implementation for cloud infrastructure.

Collects from Security & Compliance Center, IAM Identity Services,
Activity Tracker, Key Protect, VPC, and Compliance Profiles.
Each API call becomes a RawEventData with the verbatim response.
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

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]


class IBMCloudConnector(BaseConnector):
    """Collects compliance telemetry from IBM Cloud APIs."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[ibm]")
        if not self.get_secret("WLK_IBM_API_KEY"):
            errors.append("WLK_IBM_API_KEY env var not set")
        if not self.config.settings.get("account_id"):
            errors.append("account_id is required in connector settings")
        return errors

    def health_check(self) -> bool:
        try:
            token = self._get_iam_token()
            return bool(token)
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="ibm_cloud",
            source_type=SourceType.CLOUD,
            provider="ibm_cloud",
        )

        token = self._get_iam_token()
        account_id = self.config.settings["account_id"]
        region = self.config.settings.get("region", "us-south")

        collectors = [
            ("ibm_security_findings", self._collect_security_findings),
            ("ibm_iam_users", self._collect_iam_users),
            ("ibm_iam_groups", self._collect_iam_groups),
            ("ibm_activity_events", self._collect_activity_events),
            ("ibm_key_protect", self._collect_key_protect),
            ("ibm_security_groups", self._collect_security_groups),
            ("ibm_compliance_profiles", self._collect_compliance_profiles),
        ]

        for event_type, collector_fn in collectors:
            try:
                data = collector_fn(token, account_id, region)
                result.events.append(RawEventData(
                    source="ibm_cloud",
                    source_type=SourceType.CLOUD,
                    provider="ibm_cloud",
                    event_type=event_type,
                    raw_data={
                        "account_id": account_id,
                        "region": region,
                        "response": data,
                    },
                    observed_at=datetime.now(timezone.utc),
                ))
            except Exception as e:
                log.debug("IBM Cloud %s failed: %s", event_type, e)
                result.errors.append(f"{event_type}: {e}")

        result.complete()
        return result

    # -- Auth --

    def _get_iam_token(self) -> str:
        """Exchange API key for IAM bearer token."""
        resp = httpx.post(
            "https://iam.cloud.ibm.com/identity/token",
            data={
                "grant_type": "urn:ibm:params:oauth:grant-type:apikey",
                "apikey": self.get_secret("WLK_IBM_API_KEY"),
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    def _auth_headers(self, token: str) -> dict:
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }

    # -- Collectors --

    def _collect_security_findings(
        self, token: str, account_id: str, region: str
    ) -> dict:
        """Security & Compliance Center findings via Security Advisor API."""
        base = f"https://{region}.secadvisor.cloud.ibm.com"
        resp = httpx.get(
            f"{base}/v1/{account_id}/providers/{account_id}/occurrences",
            headers=self._auth_headers(token),
            timeout=self.config.timeout_seconds,
        )
        resp.raise_for_status()
        return resp.json()

    def _collect_iam_users(
        self, token: str, account_id: str, region: str
    ) -> dict:
        """IAM Identity Services — list users."""
        resp = httpx.get(
            f"https://iam.cloud.ibm.com/v2/accounts/{account_id}/users",
            headers=self._auth_headers(token),
            timeout=self.config.timeout_seconds,
        )
        resp.raise_for_status()
        return resp.json()

    def _collect_iam_groups(
        self, token: str, account_id: str, region: str
    ) -> dict:
        """IAM access groups."""
        resp = httpx.get(
            "https://iam.cloud.ibm.com/v2/groups",
            params={"account_id": account_id},
            headers=self._auth_headers(token),
            timeout=self.config.timeout_seconds,
        )
        resp.raise_for_status()
        return resp.json()

    def _collect_activity_events(
        self, token: str, account_id: str, region: str
    ) -> dict:
        """Activity Tracker events (LogDNA-compatible)."""
        from datetime import timedelta

        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=24)
        resp = httpx.get(
            f"https://api.{region}.logging.cloud.ibm.com/v1/events",
            params={
                "from": int(start.timestamp()),
                "to": int(now.timestamp()),
                "size": 500,
            },
            headers=self._auth_headers(token),
            timeout=self.config.timeout_seconds,
        )
        resp.raise_for_status()
        return resp.json()

    def _collect_key_protect(
        self, token: str, account_id: str, region: str
    ) -> dict:
        """Key Protect — list encryption keys."""
        base = f"https://{region}.kms.cloud.ibm.com"
        resp = httpx.get(
            f"{base}/api/v2/keys",
            headers={
                **self._auth_headers(token),
                "bluemix-instance": account_id,
            },
            timeout=self.config.timeout_seconds,
        )
        resp.raise_for_status()
        return resp.json()

    def _collect_security_groups(
        self, token: str, account_id: str, region: str
    ) -> dict:
        """VPC security groups."""
        base = f"https://{region}.iaas.cloud.ibm.com"
        resp = httpx.get(
            f"{base}/v1/security_groups",
            params={
                "version": "2024-01-01",
                "generation": 2,
            },
            headers=self._auth_headers(token),
            timeout=self.config.timeout_seconds,
        )
        resp.raise_for_status()
        return resp.json()

    def _collect_compliance_profiles(
        self, token: str, account_id: str, region: str
    ) -> dict:
        """Security & Compliance Center posture profiles."""
        base = f"https://{region}.compliance.cloud.ibm.com"
        resp = httpx.get(
            f"{base}/posture/v2/profiles",
            params={"account_id": account_id},
            headers=self._auth_headers(token),
            timeout=self.config.timeout_seconds,
        )
        resp.raise_for_status()
        return resp.json()


# Register
registry.register("ibm_cloud", IBMCloudConnector)
