"""OCI connector — Layer 1 implementation for Oracle Cloud Infrastructure.

Collects from Cloud Guard, IAM, Audit Events, Vulnerability Scanning,
Network Security Lists, Vault, and Bastion.
Each API call becomes a RawEventData with the verbatim response.

Uses the OCI Python SDK when available; falls back to httpx with
token-based auth via WLK_OCI_TOKEN.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from warlock.connectors.base import (
    BaseConnector,
    ConnectorResult,
    RawEventData,
    SourceType,
    registry,
)

log = logging.getLogger(__name__)

# Base URL patterns per OCI service
_SERVICE_URLS = {
    "cloud_guard": "https://cloudguard-cp-api.{region}.oci.oraclecloud.com",
    "identity": "https://identity.{region}.oraclecloud.com",
    "audit": "https://audit.{region}.oraclecloud.com",
    "vulnerability": "https://vulnerability-scanning-api.{region}.oci.oraclecloud.com",
    "core": "https://iaas.{region}.oraclecloud.com",
    "kms": "https://kms.{region}.oraclecloud.com",
    "bastion": "https://bastion.{region}.oci.oraclecloud.com",
}


def _base_url(service: str, region: str) -> str:
    return _SERVICE_URLS[service].format(region=region)


class OCIConnector(BaseConnector):
    """Collects compliance telemetry from OCI APIs."""

    def validate(self) -> list[str]:
        errors = []
        if not self.config.settings.get("compartment_id"):
            errors.append("compartment_id is required in connector settings")
        if not self.config.settings.get("tenancy_id"):
            errors.append("tenancy_id is required in connector settings")
        if not self.config.settings.get("region"):
            errors.append("region is required in connector settings")

        # Check for either SDK or token auth
        has_sdk = False
        try:
            import oci  # noqa: F401

            has_sdk = True
        except ImportError:
            pass

        if not has_sdk and not self.get_secret("WLK_OCI_TOKEN"):
            errors.append(
                "Either install oci SDK (pip install warlock[oci]) "
                "or set WLK_OCI_TOKEN for token auth"
            )
        return errors

    def health_check(self) -> bool:
        try:
            region = self.config.settings["region"]
            tenancy_id = self.config.settings["tenancy_id"]
            client = self._get_client()

            if client is not None:
                # SDK path
                resp = client.get(
                    f"https://identity.{region}.oraclecloud.com/20160918/tenancies/{tenancy_id}"
                )
                return resp.status == 200
            else:
                # httpx path
                import httpx

                headers = self._httpx_headers()
                url = f"https://identity.{region}.oraclecloud.com/20160918/tenancies/{tenancy_id}"
                resp = httpx.get(url, headers=headers, timeout=30)
                return resp.status_code == 200
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="oci",
            source_type=SourceType.CLOUD,
            provider="oci",
        )

        compartment_id = self.config.settings["compartment_id"]
        tenancy_id = self.config.settings["tenancy_id"]
        region = self.config.settings["region"]

        collectors = [
            ("oci_cloud_guard_problems", self._collect_cloud_guard_problems),
            ("oci_iam_users", self._collect_iam_users),
            ("oci_iam_groups", self._collect_iam_groups),
            ("oci_audit_events", self._collect_audit_events),
            ("oci_vulnerabilities", self._collect_vulnerabilities),
            ("oci_security_lists", self._collect_security_lists),
            ("oci_vaults", self._collect_vaults),
            ("oci_bastions", self._collect_bastions),
        ]

        for event_type, collector_fn in collectors:
            try:
                data = collector_fn(compartment_id, tenancy_id, region)
                result.events.append(
                    RawEventData(
                        source="oci",
                        source_type=SourceType.CLOUD,
                        provider="oci",
                        event_type=event_type,
                        raw_data={
                            "compartment_id": compartment_id,
                            "tenancy_id": tenancy_id,
                            "region": region,
                            "response": data,
                        },
                        observed_at=datetime.now(timezone.utc),
                    )
                )
            except Exception as e:
                log.debug("OCI %s failed: %s", event_type, e)
                result.errors.append(f"{event_type}: {e}")

        result.complete()
        return result

    # -- Auth helpers --

    def _get_client(self):
        """Return an OCI SDK signer-based session, or None if SDK unavailable."""
        try:
            import oci

            user_ocid = self.get_secret("WLK_OCI_USER_OCID")
            key_file = self.get_secret("WLK_OCI_KEY_FILE")
            fingerprint = self.get_secret("WLK_OCI_FINGERPRINT")
            tenancy = self.get_secret("WLK_OCI_TENANCY") or self.config.settings.get(
                "tenancy_id", ""
            )

            config = {
                "user": user_ocid,
                "key_file": key_file,
                "fingerprint": fingerprint,
                "tenancy": tenancy,
                "region": self.config.settings["region"],
            }
            oci.config.validate_config(config)
            return oci.base_client.BaseClient(
                service="",
                config=config,
                signer=oci.signer.Signer(
                    tenancy=tenancy,
                    user=user_ocid,
                    fingerprint=fingerprint,
                    private_key_file_location=key_file,
                ),
                type_mapping={},
            )
        except (ImportError, Exception):
            return None

    def _httpx_headers(self) -> dict[str, str]:
        """Headers for httpx fallback using bearer token."""
        token = self.get_secret("WLK_OCI_TOKEN")
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

    def _get(self, url: str, params: dict | None = None) -> dict:
        """Make a GET request using SDK or httpx."""
        client = self._get_client()

        if client is not None:
            response = client.call_api(
                resource_path=url.split(".com")[-1],
                method="GET",
                query_params=params or {},
                header_params={"accept": "application/json"},
            )
            return response.data if isinstance(response.data, dict) else {"items": response.data}

        import httpx

        headers = self._httpx_headers()
        resp = httpx.get(url, params=params or {}, headers=headers, timeout=60)
        resp.raise_for_status()
        return resp.json()

    # -- Collectors --

    def _collect_cloud_guard_problems(
        self, compartment_id: str, tenancy_id: str, region: str
    ) -> dict:
        base = _base_url("cloud_guard", region)
        url = f"{base}/20200131/problems"
        params = {
            "compartmentId": compartment_id,
            "riskLevel": "CRITICAL,HIGH",
            "lifecycleState": "ACTIVE",
            "sortBy": "riskLevel",
            "sortOrder": "DESC",
            "limit": "200",
        }
        data = self._get(url, params)
        return {
            "problems": data.get("items", []),
        }

    def _collect_iam_users(self, compartment_id: str, tenancy_id: str, region: str) -> dict:
        base = _base_url("identity", region)
        url = f"{base}/20160918/users"
        params = {"compartmentId": tenancy_id, "limit": "200"}
        data = self._get(url, params)
        return {
            "users": data.get("items", data.get("users", [])),
        }

    def _collect_iam_groups(self, compartment_id: str, tenancy_id: str, region: str) -> dict:
        base = _base_url("identity", region)
        url = f"{base}/20160918/groups"
        params = {"compartmentId": tenancy_id, "limit": "200"}
        data = self._get(url, params)
        return {
            "groups": data.get("items", data.get("groups", [])),
        }

    def _collect_audit_events(self, compartment_id: str, tenancy_id: str, region: str) -> dict:
        base = _base_url("audit", region)
        url = f"{base}/20190901/auditEvents"
        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=24)
        params = {
            "compartmentId": compartment_id,
            "startTime": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "endTime": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "limit": "500",
        }
        data = self._get(url, params)
        return {
            "audit_events": data.get("items", data.get("auditEvents", [])),
        }

    def _collect_vulnerabilities(self, compartment_id: str, tenancy_id: str, region: str) -> dict:
        base = _base_url("vulnerability", region)
        url = f"{base}/20210630/hostVulnerabilities"
        params = {
            "compartmentId": compartment_id,
            "limit": "200",
        }
        data = self._get(url, params)
        return {
            "vulnerabilities": data.get("items", data.get("hostVulnerabilities", [])),
        }

    def _collect_security_lists(self, compartment_id: str, tenancy_id: str, region: str) -> dict:
        base = _base_url("core", region)
        url = f"{base}/20160918/securityLists"
        params = {"compartmentId": compartment_id, "limit": "200"}
        data = self._get(url, params)
        return {
            "security_lists": data.get("items", data.get("securityLists", [])),
        }

    def _collect_vaults(self, compartment_id: str, tenancy_id: str, region: str) -> dict:
        base = _base_url("kms", region)
        url = f"{base}/20180608/vaults"
        params = {"compartmentId": compartment_id, "limit": "200"}
        data = self._get(url, params)
        return {
            "vaults": data.get("items", data.get("vaults", [])),
        }

    def _collect_bastions(self, compartment_id: str, tenancy_id: str, region: str) -> dict:
        base = _base_url("bastion", region)
        url = f"{base}/20210331/bastions"
        params = {"compartmentId": compartment_id, "limit": "200"}
        data = self._get(url, params)
        return {
            "bastions": data.get("items", data.get("bastions", [])),
        }


# Register
registry.register("oci", OCIConnector)
