"""AWS connector — Layer 1 implementation for cloud infrastructure.

Collects from IAM, CloudTrail, EC2, GuardDuty, SecurityHub, etc.
Each API call becomes a RawEventData with the verbatim response.
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

# Service → list of (method, event_type) to collect
# "method" is the boto3 client method name
AWS_CHECKS: dict[str, list[tuple[str, str]]] = {
    "iam": [
        ("generate_credential_report|get_credential_report", "iam_credential_report"),
        ("list_users", "iam_users"),
        ("list_policies", "iam_policies"),
        ("get_account_summary", "iam_account_summary"),
        ("get_account_password_policy", "iam_password_policy"),
    ],
    "cloudtrail": [
        ("describe_trails", "cloudtrail_trails"),
        ("get_trail_status", "cloudtrail_status"),
    ],
    "ec2": [
        ("describe_security_groups", "ec2_security_groups"),
        ("describe_network_acls", "ec2_network_acls"),
        ("describe_vpcs", "ec2_vpcs"),
        ("describe_flow_logs", "ec2_flow_logs"),
    ],
    "guardduty": [
        ("list_detectors", "guardduty_detectors"),
    ],
    "securityhub": [
        ("describe_hub", "securityhub_hub"),
    ],
    "s3": [
        ("list_buckets", "s3_buckets"),
    ],
    "config": [
        ("describe_configuration_recorders", "config_recorders"),
        ("describe_compliance_by_config_rule", "config_compliance"),
    ],
}

# Services that are global (not regional)
GLOBAL_SERVICES = {"iam", "s3", "cloudfront", "route53", "organizations"}


class AWSConnector(BaseConnector):
    """Collects compliance telemetry from AWS APIs."""

    def validate(self) -> list[str]:
        errors = []
        try:
            import boto3  # noqa: F401
        except ImportError:
            errors.append("boto3 not installed. Install with: pip install warlock[aws]")
        return errors

    def health_check(self) -> bool:
        try:
            import boto3
            sts = boto3.client("sts", **self._client_kwargs())
            sts.get_caller_identity()
            return True
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import boto3

        result = ConnectorResult(
            connector_name=self.name,
            source="aws",
            source_type=SourceType.CLOUD,
            provider="aws",
        )

        regions = self.config.settings.get("regions", ["us-east-1"])

        for service, checks in AWS_CHECKS.items():
            service_regions = [regions[0]] if service in GLOBAL_SERVICES else regions

            for region in service_regions:
                try:
                    client = boto3.client(service, region_name=region, **self._client_kwargs())
                except Exception as e:
                    result.errors.append(f"{service}/{region}: client creation failed: {e}")
                    continue

                for method_spec, event_type in checks:
                    try:
                        data = self._call(client, method_spec)
                        result.events.append(RawEventData(
                            source="aws",
                            source_type=SourceType.CLOUD,
                            provider="aws",
                            event_type=event_type,
                            raw_data={
                                "service": service,
                                "method": method_spec,
                                "region": region,
                                "account_id": self.config.settings.get("account_id", ""),
                                "response": data,
                            },
                            observed_at=datetime.now(timezone.utc),
                        ))
                    except Exception as e:
                        log.debug("AWS %s/%s/%s failed: %s", service, method_spec, region, e)
                        result.errors.append(f"{service}/{method_spec}/{region}: {e}")

        result.complete()
        return result

    def _client_kwargs(self) -> dict:
        kwargs = {}
        role_arn = self.config.settings.get("assume_role_arn", "")
        if role_arn:
            import boto3
            sts = boto3.client("sts")
            creds = sts.assume_role(
                RoleArn=role_arn, RoleSessionName="warlock-collector"
            )["Credentials"]
            kwargs = {
                "aws_access_key_id": creds["AccessKeyId"],
                "aws_secret_access_key": creds["SecretAccessKey"],
                "aws_session_token": creds["SessionToken"],
            }
        return kwargs

    def _call(self, client, method_spec: str) -> dict:
        """Call a boto3 method. Handles chained calls like 'generate|get'."""
        methods = method_spec.split("|")
        for method_name in methods:
            fn = getattr(client, method_name)
            response = fn()
            # Strip ResponseMetadata
            response.pop("ResponseMetadata", None)
        return response


# Register
registry.register("aws", AWSConnector)
