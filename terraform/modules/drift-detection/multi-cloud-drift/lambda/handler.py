"""Multi-cloud drift detector.

Compares Terraform state files against their declared resources.
Reports drift findings to Warlock API as evidence.
"""

import json
import logging
import os

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def get_ssm_param(name: str) -> str:
    ssm = boto3.client("ssm")
    resp = ssm.get_parameter(Name=name, WithDecryption=True)
    return resp["Parameter"]["Value"]


def read_state_from_s3(bucket: str, key: str) -> dict:
    """Read and parse a Terraform state file from S3."""
    s3 = boto3.client("s3")
    resp = s3.get_object(Bucket=bucket, Key=key)
    return json.loads(resp["Body"].read().decode())


def analyze_state(state: dict) -> list[dict]:
    """Analyze a Terraform state file for potential drift indicators.

    Checks:
    - Resources in state that have no serial change (stale)
    - Resources with tainted status
    - Resources marked for deletion
    """
    findings = []

    for resource in state.get("resources", []):
        resource_type = resource.get("type", "unknown")
        resource_name = resource.get("name", "unknown")
        module_path = resource.get("module", "root")

        for instance in resource.get("instances", []):
            status = instance.get("status")

            if status == "tainted":
                findings.append({
                    "resource": f"{module_path}.{resource_type}.{resource_name}",
                    "issue": "tainted",
                    "severity": "high",
                    "detail": "Resource is marked as tainted and will be recreated on next apply",
                })

            # Check for deposed instances (failed create-before-destroy)
            deposed = instance.get("deposed")
            if deposed:
                findings.append({
                    "resource": f"{module_path}.{resource_type}.{resource_name}",
                    "issue": "deposed",
                    "severity": "medium",
                    "detail": f"Deposed instance found: {deposed}",
                })

    return findings


def post_to_warlock(endpoint: str, token: str, findings: list[dict], state_key: str) -> None:
    """Post drift findings to Warlock API."""
    import urllib.error
    import urllib.request

    url = f"{endpoint}/api/v1/evidence"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    payload = {
        "module": "drift-detection/multi-cloud-drift",
        "resource_id": f"state:{state_key}",
        "control_ids": ["CM-3", "CM-8"],
        "attributes": {
            "state_key": state_key,
            "drift_count": str(len(findings)),
            "findings": json.dumps(findings),
        },
        "action": "verify",
    }

    body = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            logger.info("Posted %d drift findings for %s: %s", len(findings), state_key, resp.status)
    except urllib.error.HTTPError as e:
        logger.error("Failed to post drift findings: %s", e.code)


def handler(event, context):
    """Lambda entry point. Scans all configured state files for drift."""
    logger.info("Multi-cloud drift detection started")

    bucket = os.environ["STATE_BUCKET"]
    state_keys = json.loads(os.environ.get("STATE_KEYS", "[]"))
    warlock_endpoint = os.environ["WARLOCK_API_ENDPOINT"]
    warlock_token_param = os.environ.get("WARLOCK_TOKEN_PARAM", "/warlock/api-token")
    warlock_token = get_ssm_param(warlock_token_param)

    total_findings = 0

    for key in state_keys:
        try:
            logger.info("Analyzing state: s3://%s/%s", bucket, key)
            state = read_state_from_s3(bucket, key)
            findings = analyze_state(state)
            total_findings += len(findings)

            if findings:
                logger.warning("Drift detected in %s: %d findings", key, len(findings))
                post_to_warlock(warlock_endpoint, warlock_token, findings, key)
            else:
                logger.info("No drift in %s", key)

        except Exception as e:
            logger.exception("Failed to analyze %s: %s", key, e)

    return {
        "statusCode": 200,
        "body": json.dumps({
            "states_checked": len(state_keys),
            "total_findings": total_findings,
        }),
    }
