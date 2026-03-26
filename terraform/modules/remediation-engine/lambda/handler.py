"""Remediation Engine Lambda — bridges Warlock API to Terraform Cloud.

Receives remediation requests, creates Terraform Cloud runs,
and reports results back to Warlock.
"""

import json
import logging
import os
import time
import urllib.request
import urllib.error

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TFC_API = "https://app.terraform.io/api/v2"


def get_ssm_param(name: str) -> str:
    """Retrieve a SecureString parameter from SSM."""
    ssm = boto3.client("ssm")
    resp = ssm.get_parameter(Name=name, WithDecryption=True)
    return resp["Parameter"]["Value"]


def tfc_request(method: str, path: str, token: str, data: dict | None = None) -> dict:
    """Make a Terraform Cloud API request."""
    url = f"{TFC_API}{path}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/vnd.api+json",
    }
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        logger.error("TFC API error: %s %s -> %s", method, path, e.code)
        raise


def find_or_create_workspace(token: str, org: str, workspace_name: str) -> str:
    """Find existing workspace or create a new one. Returns workspace ID."""
    # Try to find existing
    try:
        resp = tfc_request("GET", f"/organizations/{org}/workspaces/{workspace_name}", token)
        return resp["data"]["id"]
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise

    # Create new workspace
    payload = {
        "data": {
            "type": "workspaces",
            "attributes": {
                "name": workspace_name,
                "auto-apply": False,
                "execution-mode": "remote",
                "description": f"Warlock remediation workspace for {workspace_name}",
            },
        }
    }
    resp = tfc_request("POST", f"/organizations/{org}/workspaces", token, payload)
    return resp["data"]["id"]


def create_run(token: str, workspace_id: str, variables: dict, is_plan_only: bool) -> str:
    """Create a Terraform Cloud run. Returns run ID."""
    # Set workspace variables
    for key, value in variables.items():
        var_payload = {
            "data": {
                "type": "vars",
                "attributes": {
                    "key": key,
                    "value": str(value),
                    "category": "terraform",
                    "hcl": False,
                    "sensitive": key.lower().endswith(("token", "secret", "password", "key")),
                },
                "relationships": {
                    "workspace": {"data": {"id": workspace_id, "type": "workspaces"}}
                },
            }
        }
        try:
            tfc_request("POST", "/vars", token, var_payload)
        except urllib.error.HTTPError as e:
            if e.code == 422:  # Variable already exists — update it
                logger.info("Variable %s already exists, skipping", key)
            else:
                raise

    # Create the run
    run_payload = {
        "data": {
            "type": "runs",
            "attributes": {
                "is-destroy": False,
                "plan-only": is_plan_only,
                "message": f"Warlock remediation engine {'plan' if is_plan_only else 'apply'}",
            },
            "relationships": {
                "workspace": {"data": {"id": workspace_id, "type": "workspaces"}}
            },
        }
    }
    resp = tfc_request("POST", "/runs", token, run_payload)
    return resp["data"]["id"]


def wait_for_run(token: str, run_id: str, timeout: int = 240) -> dict:
    """Poll for run completion. Returns final run data."""
    terminal = {
        "applied",
        "planned",
        "planned_and_finished",
        "errored",
        "discarded",
        "canceled",
        "force_canceled",
    }
    start = time.time()
    while time.time() - start < timeout:
        resp = tfc_request("GET", f"/runs/{run_id}", token)
        status = resp["data"]["attributes"]["status"]
        logger.info("Run %s status: %s", run_id, status)
        if status in terminal:
            return resp["data"]
        time.sleep(10)
    raise TimeoutError(f"Run {run_id} did not complete within {timeout}s")


def post_evidence(warlock_endpoint: str, warlock_token: str, evidence: dict) -> None:
    """POST evidence back to Warlock API."""
    url = f"{warlock_endpoint}/api/v1/evidence"
    headers = {
        "Authorization": f"Bearer {warlock_token}",
        "Content-Type": "application/json",
    }
    body = json.dumps(evidence).encode()
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            logger.info("Evidence posted: %s", resp.status)
    except urllib.error.HTTPError as e:
        logger.error("Failed to post evidence: %s", e.code)


def handler(event, context):
    """Lambda entry point.

    Expected event:
    {
        "remediation_id": "uuid",
        "module_name": "encryption/aws-kms",
        "variables": {"name_prefix": "warlock", ...},
        "dry_run": true
    }
    """
    logger.info("Remediation engine invoked: %s", json.dumps(event))

    # Get credentials from SSM
    tfc_token_param = os.environ.get("TFC_TOKEN_PARAM", "/warlock/tfc-token")
    warlock_token_param = os.environ.get("WARLOCK_TOKEN_PARAM", "/warlock/api-token")
    tfc_token = get_ssm_param(tfc_token_param)
    warlock_token = get_ssm_param(warlock_token_param)

    tfc_org = os.environ["TFC_ORG"]
    warlock_endpoint = os.environ["WARLOCK_API_ENDPOINT"]

    remediation_id = event["remediation_id"]
    module_name = event["module_name"]
    variables = event.get("variables", {})
    dry_run = event.get("dry_run", True)

    # Create workspace name from module (e.g. "encryption-aws-kms")
    workspace_name = f"warlock-{module_name.replace('/', '-')}"

    try:
        # Find or create workspace
        workspace_id = find_or_create_workspace(tfc_token, tfc_org, workspace_name)
        logger.info("Workspace: %s (%s)", workspace_name, workspace_id)

        # Inject warlock registration variables
        variables["warlock_api_endpoint"] = warlock_endpoint
        variables["warlock_api_token"] = warlock_token
        variables["warlock_remediation_id"] = remediation_id

        # Create and wait for run
        run_id = create_run(tfc_token, workspace_id, variables, is_plan_only=dry_run)
        logger.info("Run created: %s (dry_run=%s)", run_id, dry_run)

        run_data = wait_for_run(tfc_token, run_id)
        status = run_data["attributes"]["status"]
        logger.info("Run completed: %s -> %s", run_id, status)

        # Post evidence back to Warlock
        post_evidence(
            warlock_endpoint,
            warlock_token,
            {
                "module": module_name,
                "resource_id": f"tfc-run:{run_id}",
                "control_ids": [],  # Will be populated from module's remediation.tf
                "attributes": {
                    "run_id": run_id,
                    "workspace": workspace_name,
                    "status": status,
                    "dry_run": str(dry_run),
                },
                "action": "verify" if dry_run else "remediate",
                "remediation_id": remediation_id,
            },
        )

        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "remediation_id": remediation_id,
                    "run_id": run_id,
                    "status": status,
                    "dry_run": dry_run,
                }
            ),
        }

    except Exception as e:
        logger.exception("Remediation engine failed: %s", e)
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e), "remediation_id": remediation_id}),
        }
