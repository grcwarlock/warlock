"""Huawei Cloud connector — Layer 1 implementation for cloud infrastructure.

Collects from Host Security Service (HSS), IAM, Cloud Trace Service (CTS),
VPC Security Groups, Key Management Service (KMS), and Object Storage (OBS).
Uses Huawei Cloud REST APIs via httpx with AKSK token authentication.
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


class HuaweiCloudConnector(BaseConnector):
    """Collects compliance telemetry from Huawei Cloud APIs."""

    def validate(self) -> list[str]:
        errors = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed. Install with: pip install warlock[huawei]")
        if not self.get_secret("WLK_HUAWEI_ACCESS_KEY"):
            errors.append("WLK_HUAWEI_ACCESS_KEY env var is not set")
        if not self.get_secret("WLK_HUAWEI_SECRET_KEY"):
            errors.append("WLK_HUAWEI_SECRET_KEY env var is not set")
        if not self.config.settings.get("project_id"):
            errors.append("project_id is required in connector settings")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self._get_iam_token()
            resp = httpx.get(
                "https://iam.myhuaweicloud.com/v3/auth/projects",
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
            source="huawei",
            source_type=SourceType.CLOUD,
            provider="huawei",
        )

        project_id = self.config.settings["project_id"]
        region = self.config.settings.get("region", "cn-north-4")
        token = self._get_iam_token()
        headers = self._headers(token)

        collectors = [
            ("huawei_hss_events", self._collect_hss_events),
            ("huawei_iam_users", self._collect_iam_users),
            ("huawei_cts_events", self._collect_cts_events),
            ("huawei_security_groups", self._collect_security_groups),
            ("huawei_kms_keys", self._collect_kms_keys),
            ("huawei_obs_buckets", self._collect_obs_buckets),
        ]

        client = httpx.Client(
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for event_type, collector_fn in collectors:
                try:
                    data = collector_fn(client, project_id, region)
                    result.events.append(
                        RawEventData(
                            source="huawei",
                            source_type=SourceType.CLOUD,
                            provider="huawei",
                            event_type=event_type,
                            raw_data={
                                "project_id": project_id,
                                "region": region,
                                "response": data,
                            },
                            observed_at=datetime.now(timezone.utc),
                        )
                    )
                except Exception as e:
                    log.debug("Huawei %s failed: %s", event_type, e)
                    result.errors.append(f"{event_type}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    # -- Collectors --

    def _collect_hss_events(self, client, project_id: str, region: str) -> dict:
        """Host Security Service — security alerts."""
        url = f"https://hss.{region}.myhuaweicloud.com/v5/{project_id}/event/events"
        resp = client.get(url, params={"limit": 200, "offset": 0})
        resp.raise_for_status()
        return resp.json()

    def _collect_iam_users(self, client, project_id: str, region: str) -> dict:
        """IAM users list."""
        url = "https://iam.myhuaweicloud.com/v3/users"
        resp = client.get(url)
        resp.raise_for_status()
        return resp.json()

    def _collect_cts_events(self, client, project_id: str, region: str) -> dict:
        """Cloud Trace Service — audit trail events."""
        url = f"https://cts.{region}.myhuaweicloud.com/v3/{project_id}/traces"
        resp = client.get(url, params={"limit": 200})
        resp.raise_for_status()
        return resp.json()

    def _collect_security_groups(self, client, project_id: str, region: str) -> dict:
        """VPC Security Groups."""
        url = f"https://vpc.{region}.myhuaweicloud.com/v1/{project_id}/security-groups"
        resp = client.get(url)
        resp.raise_for_status()
        return resp.json()

    def _collect_kms_keys(self, client, project_id: str, region: str) -> dict:
        """Key Management Service — list encryption keys."""
        url = f"https://kms.{region}.myhuaweicloud.com/v1.0/{project_id}/kms/list-keys"
        resp = client.post(url, json={"limit": "100"})
        resp.raise_for_status()
        return resp.json()

    def _collect_obs_buckets(self, client, project_id: str, region: str) -> dict:
        """Object Storage Service — bucket listing."""
        url = f"https://obs.{region}.myhuaweicloud.com/"
        resp = client.get(url)
        resp.raise_for_status()
        # OBS returns XML; parse to dict
        return self._parse_obs_xml(resp.text)

    # -- Auth helpers --

    def _get_iam_token(self) -> str:
        """Exchange AKSK credentials for an IAM token via password-free token endpoint."""
        import httpx

        access_key = self.get_secret("WLK_HUAWEI_ACCESS_KEY")
        secret_key = self.get_secret("WLK_HUAWEI_SECRET_KEY")
        project_id = self.config.settings["project_id"]
        region = self.config.settings.get("region", "cn-north-4")

        body = {
            "auth": {
                "identity": {
                    "methods": ["hw_ak_sk"],
                    "hw_ak_sk": {
                        "access": {"key": access_key},
                        "secret": {"key": secret_key},
                    },
                },
                "scope": {
                    "project": {"id": project_id},
                },
            },
        }

        resp = httpx.post(
            f"https://iam.{region}.myhuaweicloud.com/v3/auth/tokens",
            json=body,
            timeout=30,
        )
        resp.raise_for_status()
        token = resp.headers.get("X-Subject-Token", "")
        if not token:
            raise RuntimeError("Huawei IAM token exchange returned no token")
        return token

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "X-Auth-Token": token,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    @staticmethod
    def _parse_obs_xml(xml_text: str) -> dict:
        """Minimal XML parse for OBS ListBuckets response."""
        import xml.etree.ElementTree as ET

        root = ET.fromstring(xml_text)
        ns = ""
        # Detect namespace if present
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"

        buckets = []
        buckets_elem = root.find(f"{ns}Buckets")
        if buckets_elem is not None:
            for bucket in buckets_elem.findall(f"{ns}Bucket"):
                name = bucket.findtext(f"{ns}Name", "")
                creation_date = bucket.findtext(f"{ns}CreationDate", "")
                location = bucket.findtext(f"{ns}Location", "")
                buckets.append(
                    {
                        "name": name,
                        "creation_date": creation_date,
                        "location": location,
                    }
                )

        return {"buckets": buckets}


# Register
registry.register("huawei", HuaweiCloudConnector)
