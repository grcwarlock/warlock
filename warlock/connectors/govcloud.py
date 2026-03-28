"""GovCloud connector variants — government-specific cloud endpoints (GAP-088).

Extends AWS, Azure, and GCP connectors for government environments:
- AWS GovCloud (us-gov-west-1, us-gov-east-1)
- Azure Government (*.usgovcloudapi.net)
- GCP Assured Workloads
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

# GovCloud region/endpoint mappings
GOVCLOUD_CONFIGS: dict[str, dict] = {
    "aws_govcloud": {
        "regions": ["us-gov-west-1", "us-gov-east-1"],
        "sts_endpoint": "https://sts.us-gov-west-1.amazonaws.com",
        "partition": "aws-us-gov",
    },
    "azure_gov": {
        "authority": "https://login.microsoftonline.us",
        "resource_manager": "https://management.usgovcloudapi.net",
        "graph_endpoint": "https://graph.microsoft.us/v1.0",
    },
    "gcp_assured": {
        "assured_workloads_endpoint": "https://assuredworkloads.googleapis.com/v1",
        "org_policy_endpoint": "https://orgpolicy.googleapis.com/v2",
    },
}

# AWS GovCloud service checks
_AWS_GOV_CHECKS: list[tuple[str, str, str]] = [
    ("iam", "list_users", "govcloud_iam_users"),
    ("iam", "get_account_summary", "govcloud_iam_summary"),
    ("cloudtrail", "describe_trails", "govcloud_cloudtrail"),
    ("guardduty", "list_detectors", "govcloud_guardduty"),
    ("config", "describe_compliance_by_config_rule", "govcloud_config_compliance"),
]


class GovCloudConnector(BaseConnector):
    """Collects compliance telemetry from government cloud environments."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        gov_type = self.config.settings.get("gov_type", "aws_govcloud")
        if gov_type not in GOVCLOUD_CONFIGS:
            errors.append(f"Unknown gov_type={gov_type}. Options: {', '.join(GOVCLOUD_CONFIGS)}")

        if gov_type == "aws_govcloud":
            try:
                import boto3  # noqa: F401
            except ImportError:
                errors.append("boto3 not installed")
        elif gov_type in ("azure_gov", "gcp_assured"):
            try:
                import httpx  # noqa: F401
            except ImportError:
                errors.append("httpx not installed")

        return errors

    def health_check(self) -> bool:
        gov_type = self.config.settings.get("gov_type", "aws_govcloud")
        try:
            if gov_type == "aws_govcloud":
                return self._aws_health()
            elif gov_type == "azure_gov":
                return self._azure_health()
            elif gov_type == "gcp_assured":
                return self._gcp_health()
            return False
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        gov_type = self.config.settings.get("gov_type", "aws_govcloud")

        if gov_type == "aws_govcloud":
            return self._collect_aws_govcloud()
        elif gov_type == "azure_gov":
            return self._collect_azure_gov()
        elif gov_type == "gcp_assured":
            return self._collect_gcp_assured()

        result = ConnectorResult(
            connector_name=self.name,
            source="govcloud",
            source_type=SourceType.CLOUD,
            provider="govcloud",
        )
        result.errors.append(f"Unknown gov_type: {gov_type}")
        result.complete()
        return result

    # -- AWS GovCloud --

    def _aws_health(self) -> bool:
        import boto3

        config = GOVCLOUD_CONFIGS["aws_govcloud"]
        sts = boto3.client(
            "sts",
            region_name=config["regions"][0],
            endpoint_url=config["sts_endpoint"],
        )
        sts.get_caller_identity()
        return True

    def _collect_aws_govcloud(self) -> ConnectorResult:
        import boto3

        result = ConnectorResult(
            connector_name=self.name,
            source="govcloud",
            source_type=SourceType.CLOUD,
            provider="aws_govcloud",
        )
        config = GOVCLOUD_CONFIGS["aws_govcloud"]
        regions = config["regions"]

        for region in regions:
            for service, method, event_type in _AWS_GOV_CHECKS:
                try:
                    client = boto3.client(service, region_name=region)
                    fn = getattr(client, method)
                    resp = fn()
                    resp.pop("ResponseMetadata", None)
                    result.events.append(
                        RawEventData(
                            source="govcloud",
                            source_type=SourceType.CLOUD,
                            provider="aws_govcloud",
                            event_type=event_type,
                            raw_data={
                                "service": service,
                                "method": method,
                                "region": region,
                                "partition": config["partition"],
                                "response": resp,
                            },
                            observed_at=datetime.now(timezone.utc),
                        )
                    )
                except Exception as e:
                    log.debug("AWS GovCloud %s/%s/%s failed: %s", service, method, region, e)
                    result.errors.append(f"{event_type}/{region}: {e}")

        result.complete()
        return result

    # -- Azure Government --

    def _azure_health(self) -> bool:
        import httpx

        config = GOVCLOUD_CONFIGS["azure_gov"]
        token = self.get_secret("WLK_AZURE_GOV_TOKEN")
        resp = httpx.get(
            f"{config['resource_manager']}/subscriptions",
            params={"api-version": "2022-12-01"},
            headers={"Authorization": f"Bearer {token}"},
            timeout=self.config.timeout_seconds,
        )
        return resp.status_code == 200

    def _collect_azure_gov(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="govcloud",
            source_type=SourceType.CLOUD,
            provider="azure_gov",
        )
        config = GOVCLOUD_CONFIGS["azure_gov"]
        token = self.get_secret("WLK_AZURE_GOV_TOKEN")
        headers = {"Authorization": f"Bearer {token}"}

        endpoints = [
            ("/subscriptions", "azure_gov_subscriptions"),
            ("/providers/Microsoft.Security/secureScores", "azure_gov_secure_scores"),
            (
                "/providers/Microsoft.PolicyInsights/policyStates/latest/summarize",
                "azure_gov_policy",
            ),
        ]

        client = httpx.Client(
            base_url=config["resource_manager"],
            headers=headers,
            timeout=self.config.timeout_seconds,
        )
        try:
            for endpoint, event_type in endpoints:
                try:
                    resp = client.get(endpoint, params={"api-version": "2022-12-01"})
                    resp.raise_for_status()
                    result.events.append(
                        RawEventData(
                            source="govcloud",
                            source_type=SourceType.CLOUD,
                            provider="azure_gov",
                            event_type=event_type,
                            raw_data={"endpoint": endpoint, "response": resp.json()},
                            observed_at=datetime.now(timezone.utc),
                        )
                    )
                except Exception as e:
                    log.debug("Azure Gov %s failed: %s", endpoint, e)
                    result.errors.append(f"{event_type}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    # -- GCP Assured Workloads --

    def _gcp_health(self) -> bool:
        import httpx

        config = GOVCLOUD_CONFIGS["gcp_assured"]
        token = self.get_secret("WLK_GCP_ASSURED_TOKEN")
        resp = httpx.get(
            f"{config['assured_workloads_endpoint']}/organizations/-/locations/-/workloads",
            headers={"Authorization": f"Bearer {token}"},
            timeout=self.config.timeout_seconds,
        )
        return resp.status_code in (200, 403)  # 403 = auth works, no perms

    def _collect_gcp_assured(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="govcloud",
            source_type=SourceType.CLOUD,
            provider="gcp_assured",
        )
        config = GOVCLOUD_CONFIGS["gcp_assured"]
        token = self.get_secret("WLK_GCP_ASSURED_TOKEN")
        org_id = self.config.settings.get("gcp_org_id", "")
        headers = {"Authorization": f"Bearer {token}"}

        endpoints = [
            (
                f"{config['assured_workloads_endpoint']}/organizations/{org_id}/locations/-/workloads",
                "gcp_assured_workloads",
            ),
            (
                f"{config['org_policy_endpoint']}/organizations/{org_id}/policies",
                "gcp_assured_org_policies",
            ),
        ]

        client = httpx.Client(headers=headers, timeout=self.config.timeout_seconds)
        try:
            for url, event_type in endpoints:
                try:
                    resp = client.get(url)
                    resp.raise_for_status()
                    result.events.append(
                        RawEventData(
                            source="govcloud",
                            source_type=SourceType.CLOUD,
                            provider="gcp_assured",
                            event_type=event_type,
                            raw_data={"url": url, "response": resp.json()},
                            observed_at=datetime.now(timezone.utc),
                        )
                    )
                except Exception as e:
                    log.debug("GCP Assured %s failed: %s", url, e)
                    result.errors.append(f"{event_type}: {e}")
        finally:
            client.close()

        result.complete()
        return result


registry.register("govcloud", GovCloudConnector)
