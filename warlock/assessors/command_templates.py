"""Remediation command templates: provider-specific CLI, Terraform, and console URLs.

Given a (provider, resource_type) pair, returns template strings that can be
formatted with the actual resource_id to produce copy-paste-ready commands.
"""

from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# Template registry: (provider_pattern, resource_type_pattern) -> commands
#
# Provider patterns use lowercase; callers should .lower() before lookup.
# resource_type uses the Finding.resource_type value from the pipeline.
# ---------------------------------------------------------------------------

_TEMPLATES: list[dict[str, Any]] = [
    # -- AWS S3 --
    {
        "providers": ["aws"],
        "resource_types": ["s3_bucket"],
        "terraform": (
            'resource "aws_s3_bucket_server_side_encryption_configuration" "{resource_name}_enc" {{\n'
            '  bucket = "{resource_id}"\n'
            "  rule {{\n"
            "    apply_server_side_encryption_by_default {{\n"
            '      sse_algorithm = "aws:kms"\n'
            "    }}\n"
            "  }}\n"
            "}}\n\n"
            'resource "aws_s3_bucket_public_access_block" "{resource_name}_block" {{\n'
            '  bucket                  = "{resource_id}"\n'
            "  block_public_acls       = true\n"
            "  block_public_policy     = true\n"
            "  ignore_public_acls      = true\n"
            "  restrict_public_buckets = true\n"
            "}}"
        ),
        "cli": (
            "# Enable default encryption\n"
            "aws s3api put-bucket-encryption \\\n"
            "  --bucket {resource_id} \\\n"
            '  --server-side-encryption-configuration \'{{"Rules":[{{"ApplyServerSideEncryptionByDefault":{{"SSEAlgorithm":"aws:kms"}}}}]}}\'\n\n'
            "# Block public access\n"
            "aws s3api put-public-access-block \\\n"
            "  --bucket {resource_id} \\\n"
            "  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
        ),
        "console_url": "https://s3.console.aws.amazon.com/s3/buckets/{resource_id}?tab=properties",
    },
    # -- AWS EC2 --
    {
        "providers": ["aws"],
        "resource_types": ["ec2_instance"],
        "terraform": (
            'resource "aws_instance" "{resource_name}" {{\n'
            "  # ... existing config ...\n"
            "  metadata_options {{\n"
            '    http_tokens = "required"  # IMDSv2\n'
            "  }}\n"
            "  monitoring = true\n"
            "}}"
        ),
        "cli": (
            "# Require IMDSv2\n"
            "aws ec2 modify-instance-metadata-options \\\n"
            "  --instance-id {resource_id} \\\n"
            "  --http-tokens required \\\n"
            "  --http-endpoint enabled\n\n"
            "# Enable detailed monitoring\n"
            "aws ec2 monitor-instances --instance-ids {resource_id}"
        ),
        "console_url": "https://console.aws.amazon.com/ec2/v2/home#InstanceDetails:instanceId={resource_id}",
    },
    # -- AWS IAM User --
    {
        "providers": ["aws"],
        "resource_types": ["iam_user"],
        "terraform": (
            'resource "aws_iam_user_login_profile" "{resource_name}" {{\n'
            "  user = aws_iam_user.{resource_name}.name\n"
            "}}\n\n"
            "# MFA enforcement via IAM policy\n"
            'resource "aws_iam_user_policy" "{resource_name}_mfa" {{\n'
            "  user = aws_iam_user.{resource_name}.name\n"
            "  policy = jsonencode({{\n"
            '    Version = "2012-10-17"\n'
            "    Statement = [{{\n"
            '      Effect = "Deny"\n'
            '      NotAction = ["iam:CreateVirtualMFADevice", "iam:EnableMFADevice", "iam:ListMFADevices", "sts:GetSessionToken"]\n'
            '      Resource = "*"\n'
            '      Condition = {{ BoolIfExists = {{ "aws:MultiFactorAuthPresent" = "false" }} }}\n'
            "    }}]\n"
            "  }})\n"
            "}}"
        ),
        "cli": (
            "# Create virtual MFA device\n"
            "aws iam create-virtual-mfa-device \\\n"
            "  --virtual-mfa-device-name {resource_id}-mfa \\\n"
            "  --outfile /tmp/{resource_id}-qr.png \\\n"
            "  --bootstrap-method QRCodePNG\n\n"
            "# List access keys (delete unused ones)\n"
            "aws iam list-access-keys --user-name {resource_id}\n\n"
            "# Delete stale access keys\n"
            "aws iam delete-access-key --user-name {resource_id} --access-key-id <KEY_ID>"
        ),
        "console_url": "https://console.aws.amazon.com/iam/home#/users/{resource_id}",
    },
    # -- AWS IAM Role --
    {
        "providers": ["aws"],
        "resource_types": ["iam_role"],
        "terraform": (
            "# Restrict trust policy to specific principals\n"
            'resource "aws_iam_role" "{resource_name}" {{\n'
            "  assume_role_policy = jsonencode({{\n"
            '    Version = "2012-10-17"\n'
            "    Statement = [{{\n"
            '      Effect = "Allow"\n'
            '      Principal = {{ Service = "ec2.amazonaws.com" }}\n'
            '      Action = "sts:AssumeRole"\n'
            "    }}]\n"
            "  }})\n"
            "}}"
        ),
        "cli": (
            "# Review trust policy\n"
            "aws iam get-role --role-name {resource_id} --query 'Role.AssumeRolePolicyDocument'\n\n"
            "# List attached policies\n"
            "aws iam list-attached-role-policies --role-name {resource_id}\n\n"
            "# Remove overly permissive inline policies\n"
            "aws iam list-role-policies --role-name {resource_id}"
        ),
        "console_url": "https://console.aws.amazon.com/iam/home#/roles/{resource_id}",
    },
    # -- AWS Security Group --
    {
        "providers": ["aws"],
        "resource_types": ["security_group"],
        "terraform": (
            'resource "aws_security_group_rule" "{resource_name}_restrict" {{\n'
            '  type              = "ingress"\n'
            "  from_port         = 22\n"
            "  to_port           = 22\n"
            '  protocol          = "tcp"\n'
            '  cidr_blocks       = ["10.0.0.0/8"]  # Replace 0.0.0.0/0\n'
            '  security_group_id = "{resource_id}"\n'
            "}}"
        ),
        "cli": (
            "# Revoke unrestricted SSH access\n"
            "aws ec2 revoke-security-group-ingress \\\n"
            "  --group-id {resource_id} \\\n"
            "  --protocol tcp --port 22 \\\n"
            "  --cidr 0.0.0.0/0\n\n"
            "# Add restricted rule\n"
            "aws ec2 authorize-security-group-ingress \\\n"
            "  --group-id {resource_id} \\\n"
            "  --protocol tcp --port 22 \\\n"
            "  --cidr 10.0.0.0/8"
        ),
        "console_url": "https://console.aws.amazon.com/ec2/v2/home#SecurityGroup:groupId={resource_id}",
    },
    # -- AWS RDS --
    {
        "providers": ["aws"],
        "resource_types": ["rds_instance", "rds_cluster"],
        "terraform": (
            'resource "aws_db_instance" "{resource_name}" {{\n'
            "  # ... existing config ...\n"
            "  storage_encrypted     = true\n"
            "  publicly_accessible   = false\n"
            "  deletion_protection   = true\n"
            "  auto_minor_version_upgrade = true\n"
            "}}"
        ),
        "cli": (
            "# Enable encryption (requires snapshot + restore for existing)\n"
            "aws rds modify-db-instance \\\n"
            "  --db-instance-identifier {resource_id} \\\n"
            "  --no-publicly-accessible \\\n"
            "  --deletion-protection \\\n"
            "  --auto-minor-version-upgrade \\\n"
            "  --apply-immediately"
        ),
        "console_url": "https://console.aws.amazon.com/rds/home#database:id={resource_id}",
    },
    # -- AWS CloudTrail --
    {
        "providers": ["aws"],
        "resource_types": ["cloudtrail_trail"],
        "terraform": (
            'resource "aws_cloudtrail" "{resource_name}" {{\n'
            "  is_multi_region_trail        = true\n"
            "  enable_log_file_validation   = true\n"
            "  include_global_service_events = true\n"
            "}}"
        ),
        "cli": (
            "# Enable multi-region + log validation\n"
            "aws cloudtrail update-trail \\\n"
            "  --name {resource_id} \\\n"
            "  --is-multi-region-trail \\\n"
            "  --enable-log-file-validation \\\n"
            "  --include-global-service-events"
        ),
        "console_url": "https://console.aws.amazon.com/cloudtrail/home#/trails",
    },
    # -- AWS GuardDuty --
    {
        "providers": ["aws"],
        "resource_types": ["guardduty_detector"],
        "cli": (
            "# Enable GuardDuty\n"
            "aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES\n\n"
            "# Enable S3 protection\n"
            "aws guardduty update-detector \\\n"
            "  --detector-id {resource_id} \\\n"
            "  --data-sources S3Logs={{Enable=true}}"
        ),
        "console_url": "https://console.aws.amazon.com/guardduty/home",
    },
    # -- Azure (generic) --
    {
        "providers": ["azure", "azure_ad", "entra_id"],
        "resource_types": [
            "virtual_machine",
            "vm",
            "nsg",
            "storage_account",
            "key_vault",
            "sql_database",
        ],
        "cli": (
            "# List resource details\n"
            "az resource show --ids {resource_id}\n\n"
            "# Enable diagnostic logging\n"
            "az monitor diagnostic-settings create \\\n"
            "  --resource {resource_id} \\\n"
            "  --name compliance-logs \\\n"
            '  --logs \'[{{"category":"allLogs","enabled":true}}]\''
        ),
        "console_url": "https://portal.azure.com/#@/resource/{resource_id}",
    },
    # -- GCP (generic) --
    {
        "providers": ["gcp", "google_cloud"],
        "resource_types": ["gce_instance", "gcs_bucket", "iam_service_account", "bigquery_dataset"],
        "cli": (
            "# Describe resource\n"
            "gcloud compute instances describe {resource_id} --format=json\n\n"
            "# Enable OS Login (for instances)\n"
            "gcloud compute instances add-metadata {resource_id} \\\n"
            "  --metadata enable-oslogin=TRUE"
        ),
        "console_url": "https://console.cloud.google.com/home/dashboard",
    },
    # -- Okta --
    {
        "providers": ["okta"],
        "resource_types": ["okta_user", "okta_policy", "okta_application"],
        "cli": (
            "# List user factors (MFA methods)\n"
            "curl -X GET https://{{OKTA_DOMAIN}}/api/v1/users/{resource_id}/factors \\\n"
            "  -H 'Authorization: SSWS {{OKTA_API_TOKEN}}'\n\n"
            "# Enroll user in MFA\n"
            "curl -X POST https://{{OKTA_DOMAIN}}/api/v1/users/{resource_id}/factors \\\n"
            "  -H 'Authorization: SSWS {{OKTA_API_TOKEN}}' \\\n"
            "  -H 'Content-Type: application/json' \\\n"
            '  -d \'{{"factorType":"token:software:totp","provider":"OKTA"}}\''
        ),
        "console_url": "https://{{OKTA_DOMAIN}}/admin/user/profile/view/{resource_id}",
    },
    # -- CrowdStrike --
    {
        "providers": ["crowdstrike"],
        "resource_types": ["crowdstrike_host", "endpoint"],
        "cli": (
            "# Check sensor version\n"
            "falconctl -g --version\n\n"
            "# Contain host (isolate from network)\n"
            "# Via API: POST /devices/entities/devices-actions/v2?action_name=contain\n"
            '# Body: {{"ids": ["{resource_id}"]}}'
        ),
        "console_url": "https://falcon.crowdstrike.com/hosts/hosts",
    },
    # -- Generic fallback --
    {
        "providers": ["*"],
        "resource_types": ["*"],
        "cli": (
            "# No provider-specific commands available.\n"
            "# Review the resource manually:\n"
            "#   Resource: {resource_id}\n"
            "#   Type: {resource_type}\n"
            "#   Provider: {provider}\n"
            "# Follow the remediation steps in the playbook above."
        ),
        "console_url": None,
    },
]


def get_command_template(
    provider: str,
    resource_type: str,
) -> dict[str, str | None]:
    """Look up the best matching command template for a provider/resource_type pair.

    Returns a dict with keys: terraform, cli, console_url (any may be None).
    Templates contain {resource_id}, {resource_name}, {resource_type}, {provider}
    placeholders for formatting.
    """
    provider_lower = (provider or "").lower()
    rtype_lower = (resource_type or "").lower()

    best: dict[str, str | None] | None = None
    fallback: dict[str, str | None] | None = None

    for t in _TEMPLATES:
        providers = [p.lower() for p in t["providers"]]
        rtypes = [r.lower() for r in t["resource_types"]]

        # Exact match
        if provider_lower in providers and rtype_lower in rtypes:
            return {
                "terraform": t.get("terraform"),
                "cli": t.get("cli"),
                "console_url": t.get("console_url"),
            }

        # Provider match, wildcard resource type
        if provider_lower in providers and "*" in rtypes and best is None:
            best = {
                "terraform": t.get("terraform"),
                "cli": t.get("cli"),
                "console_url": t.get("console_url"),
            }

        # Wildcard fallback
        if "*" in providers and "*" in rtypes:
            fallback = {
                "terraform": t.get("terraform"),
                "cli": t.get("cli"),
                "console_url": t.get("console_url"),
            }

    return best or fallback or {"terraform": None, "cli": None, "console_url": None}


def render_commands(
    provider: str,
    resource_type: str,
    resource_id: str,
) -> dict[str, str | None]:
    """Get and render command templates with the actual resource details.

    Returns dict with terraform, cli, console_url — all with placeholders filled in.
    """
    templates = get_command_template(provider, resource_type)

    # Safe resource name for terraform identifiers
    resource_name = (
        (resource_id or "resource").replace("-", "_").replace(":", "_").replace("/", "_")
    )
    if len(resource_name) > 40:
        resource_name = resource_name[:40]

    fmt = {
        "resource_id": resource_id or "unknown",
        "resource_name": resource_name,
        "resource_type": resource_type or "unknown",
        "provider": provider or "unknown",
    }

    result: dict[str, str | None] = {}
    for key in ("terraform", "cli", "console_url"):
        val = templates.get(key)
        if val:
            try:
                result[key] = val.format(**fmt)
            except (KeyError, IndexError):
                result[key] = val
        else:
            result[key] = None

    return result
