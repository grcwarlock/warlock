"""
Warlock Drift Detector — Lambda handler
Reads Terraform state from S3, compares resource attributes against live AWS
Config recorded configuration, and publishes drift findings to SNS.

NIST controls: CM-3 (Config Change Control), CM-8 (Info System Inventory)
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

s3 = boto3.client("s3")
config_client = boto3.client("config")
sns = boto3.client("sns")

STATE_BUCKET = os.environ["TF_STATE_BUCKET"]
STATE_KEY = os.environ["TF_STATE_KEY"]
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
WARLOCK_API_ENDPOINT = os.environ.get("WARLOCK_API_ENDPOINT", "")
WARLOCK_API_TOKEN = os.environ.get("WARLOCK_API_TOKEN", "")


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Entry point for the drift detection Lambda."""
    logger.info("Starting drift detection run")

    state = _load_terraform_state()
    resources = _extract_managed_resources(state)
    logger.info("Found %d managed resources in Terraform state", len(resources))

    drift_findings: list[dict[str, Any]] = []

    for resource in resources:
        resource_type = resource.get("type", "")
        resource_id = _extract_resource_id(resource)

        if not resource_id:
            continue

        config_type = _aws_resource_type_to_config(resource_type)
        if not config_type:
            logger.debug("No Config type mapping for %s — skipping", resource_type)
            continue

        live_config = _get_config_resource(config_type, resource_id)
        if live_config is None:
            drift_findings.append(
                _make_finding(
                    resource_type=resource_type,
                    resource_id=resource_id,
                    drift_type="RESOURCE_DELETED",
                    detail="Resource exists in Terraform state but is not found in AWS Config — may have been deleted out-of-band",
                    tf_attrs=resource.get("instances", [{}])[0].get("attributes", {}),
                    live_attrs={},
                )
            )
            continue

        drifts = _compare_attributes(
            resource_type=resource_type,
            resource_id=resource_id,
            tf_attrs=resource.get("instances", [{}])[0].get("attributes", {}),
            live_config=live_config,
        )
        drift_findings.extend(drifts)

    logger.info("Drift detection complete — %d finding(s)", len(drift_findings))

    if drift_findings:
        _publish_findings(drift_findings)

    return {
        "statusCode": 200,
        "resources_evaluated": len(resources),
        "drift_findings": len(drift_findings),
        "findings": drift_findings,
    }


# ── State loading ─────────────────────────────────────────────────────

def _load_terraform_state() -> dict[str, Any]:
    """Download and parse the Terraform state file from S3."""
    logger.info("Loading state from s3://%s/%s", STATE_BUCKET, STATE_KEY)
    response = s3.get_object(Bucket=STATE_BUCKET, Key=STATE_KEY)
    raw = response["Body"].read()
    return json.loads(raw)


def _extract_managed_resources(state: dict[str, Any]) -> list[dict[str, Any]]:
    """Return a flat list of all managed resources from the state tree."""
    resources: list[dict[str, Any]] = []
    for resource in state.get("resources", []):
        if resource.get("mode") == "managed":
            resources.append(resource)
    return resources


def _extract_resource_id(resource: dict[str, Any]) -> str | None:
    """Extract the primary AWS resource ID from a Terraform resource."""
    instances = resource.get("instances", [])
    if not instances:
        return None
    attrs = instances[0].get("attributes", {})
    return attrs.get("id") or attrs.get("arn")


# ── AWS Config integration ────────────────────────────────────────────

_TF_TO_CONFIG_TYPE: dict[str, str] = {
    "aws_instance": "AWS::EC2::Instance",
    "aws_s3_bucket": "AWS::S3::Bucket",
    "aws_security_group": "AWS::EC2::SecurityGroup",
    "aws_iam_role": "AWS::IAM::Role",
    "aws_kms_key": "AWS::KMS::Key",
    "aws_cloudtrail": "AWS::CloudTrail::Trail",
    "aws_guardduty_detector": "AWS::GuardDuty::Detector",
    "aws_vpc": "AWS::EC2::VPC",
    "aws_subnet": "AWS::EC2::Subnet",
    "aws_db_instance": "AWS::RDS::DBInstance",
    "aws_lambda_function": "AWS::Lambda::Function",
    "aws_eks_cluster": "AWS::EKS::Cluster",
    "aws_config_config_rule": "AWS::Config::ConfigRule",
}


def _aws_resource_type_to_config(tf_type: str) -> str | None:
    return _TF_TO_CONFIG_TYPE.get(tf_type)


def _get_config_resource(
    resource_type: str, resource_id: str
) -> dict[str, Any] | None:
    """Fetch the latest configuration for a resource from AWS Config."""
    try:
        response = config_client.get_resource_config_history(
            resourceType=resource_type,
            resourceId=resource_id,
            limit=1,
        )
        items = response.get("configurationItems", [])
        if not items:
            return None
        item = items[0]
        raw_config = item.get("configuration", "{}")
        return json.loads(raw_config) if isinstance(raw_config, str) else raw_config
    except config_client.exceptions.ResourceNotDiscoveredException:
        return None
    except Exception as exc:  # noqa: BLE001
        logger.warning("Config lookup failed for %s/%s: %s", resource_type, resource_id, exc)
        return None


# ── Attribute comparison ──────────────────────────────────────────────

# Security-critical attributes that must match — keyed by Terraform resource type
_CRITICAL_ATTRS: dict[str, list[tuple[str, str]]] = {
    "aws_s3_bucket": [
        # (tf_attr_path, config_attr_path)
        # These are simplified — real mapping depends on Config schema
    ],
    "aws_kms_key": [
        ("enable_key_rotation", "keyRotationStatus"),
    ],
    "aws_cloudtrail": [
        ("enable_log_file_validation", "logFileValidationEnabled"),
        ("is_multi_region_trail", "isMultiRegionTrail"),
    ],
    "aws_vpc": [
        ("enable_dns_hostnames", "enableDnsHostnames"),
        ("enable_dns_support", "enableDnsSupport"),
    ],
}


def _compare_attributes(
    resource_type: str,
    resource_id: str,
    tf_attrs: dict[str, Any],
    live_config: dict[str, Any],
) -> list[dict[str, Any]]:
    """Compare critical Terraform-declared attributes against live Config data."""
    findings: list[dict[str, Any]] = []
    mappings = _CRITICAL_ATTRS.get(resource_type, [])

    for tf_key, config_key in mappings:
        tf_val = tf_attrs.get(tf_key)
        live_val = live_config.get(config_key)

        # Normalise booleans from Config JSON strings
        if isinstance(live_val, str):
            if live_val.lower() == "true":
                live_val = True
            elif live_val.lower() == "false":
                live_val = False

        if tf_val is not None and live_val is not None and tf_val != live_val:
            findings.append(
                _make_finding(
                    resource_type=resource_type,
                    resource_id=resource_id,
                    drift_type="ATTRIBUTE_CHANGED",
                    detail=f"Attribute '{tf_key}' declared as {tf_val!r} in state but live value is {live_val!r}",
                    tf_attrs={tf_key: tf_val},
                    live_attrs={config_key: live_val},
                )
            )

    return findings


# ── Finding construction and publishing ──────────────────────────────

def _make_finding(
    resource_type: str,
    resource_id: str,
    drift_type: str,
    detail: str,
    tf_attrs: dict[str, Any],
    live_attrs: dict[str, Any],
) -> dict[str, Any]:
    return {
        "drift_type": drift_type,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "detail": detail,
        "terraform_declared": tf_attrs,
        "live_value": live_attrs,
        "nist_controls": ["CM-3", "CM-8"],
    }


def _publish_findings(findings: list[dict[str, Any]]) -> None:
    """Publish drift findings to the configured SNS topic."""
    message = json.dumps(
        {
            "source": "warlock-drift-detector",
            "drift_count": len(findings),
            "findings": findings,
        },
        indent=2,
        default=str,
    )
    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"[Warlock] Terraform drift detected — {len(findings)} finding(s)",
        Message=message,
    )
    logger.info("Published %d findings to SNS", len(findings))
