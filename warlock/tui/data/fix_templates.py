"""Remediation command templates by finding source/type.

Maps connector types and finding patterns to copy-pasteable CLI commands.
"""

from __future__ import annotations

# Each template: list of {step, description, commands: [str], is_terraform: bool}
FIX_TEMPLATES: dict[str, list[dict]] = {
    "aws_security_hub": [
        {
            "step": 1,
            "description": "Identify affected resources",
            "commands": [
                "aws securityhub get-findings \\",
                '  --filters \'{"ResourceId": [{"Value": "$RESOURCE_ARN", "Comparison": "EQUALS"}]}\' \\',
                "  --query 'Findings[0].Resources'",
            ],
        },
        {
            "step": 2,
            "description": "Apply remediation",
            "commands": [
                "# Review the finding details and apply the specific fix",
                "# See AWS Security Hub remediation docs for control-specific commands",
            ],
        },
        {
            "step": 3,
            "description": "Verify fix with re-scan",
            "commands": [
                "aws securityhub batch-update-findings \\",
                '  --finding-identifiers \'[{"Id": "$FINDING_ID", "ProductArn": "$PRODUCT_ARN"}]\' \\',
                '  --workflow \'{"Status": "RESOLVED"}\'',
            ],
        },
    ],
    "aws_guardduty": [
        {
            "step": 1,
            "description": "Get finding details",
            "commands": [
                "aws guardduty get-findings \\",
                "  --detector-id $DETECTOR_ID \\",
                "  --finding-ids $FINDING_ID",
            ],
        },
        {
            "step": 2,
            "description": "Archive after remediation",
            "commands": [
                "aws guardduty archive-findings \\",
                "  --detector-id $DETECTOR_ID \\",
                "  --finding-ids $FINDING_ID",
            ],
        },
    ],
    "snyk": [
        {
            "step": 1,
            "description": "Update vulnerable dependency",
            "commands": [
                "# Check current vulnerability status",
                "snyk test --severity-threshold=high",
                "",
                "# Auto-fix if available",
                "snyk fix",
            ],
        },
        {
            "step": 2,
            "description": "Verify fix",
            "commands": [
                "snyk test",
                "snyk monitor  # Update continuous monitoring",
            ],
        },
    ],
    "trivy": [
        {
            "step": 1,
            "description": "Scan and identify vulnerabilities",
            "commands": [
                "trivy image --severity HIGH,CRITICAL $IMAGE_NAME",
            ],
        },
        {
            "step": 2,
            "description": "Update base image and rebuild",
            "commands": [
                "# Update Dockerfile base image to latest patched version",
                "docker build -t $IMAGE_NAME .",
                "trivy image --severity HIGH,CRITICAL $IMAGE_NAME",
            ],
        },
    ],
    "github_advanced_security": [
        {
            "step": 1,
            "description": "Review alert details",
            "commands": [
                "gh api repos/$OWNER/$REPO/code-scanning/alerts/$ALERT_NUMBER",
            ],
        },
        {
            "step": 2,
            "description": "Fix and verify",
            "commands": [
                "# Apply code fix, then re-trigger scan",
                "gh workflow run codeql-analysis.yml",
            ],
        },
    ],
    "nessus": [
        {
            "step": 1,
            "description": "Identify affected hosts",
            "commands": [
                "# Review Nessus scan report for affected hosts",
                "# Plugin ID: $PLUGIN_ID",
                "# CVE: $CVE_ID",
            ],
        },
        {
            "step": 2,
            "description": "Apply patches",
            "commands": [
                "# For Linux hosts:",
                "ssh $HOST 'sudo apt update && sudo apt upgrade -y'",
                "",
                "# For RHEL/CentOS:",
                "ssh $HOST 'sudo yum update -y'",
            ],
        },
        {
            "step": 3,
            "description": "Re-scan to verify",
            "commands": [
                "# Trigger a re-scan of the affected hosts in Nessus",
            ],
        },
    ],
}


def get_fix_commands(source: str, finding_title: str = "") -> list[dict] | None:
    """Get fix command template for a finding source type."""
    # Exact match
    source_lower = source.lower().replace(" ", "_").replace("-", "_")
    if source_lower in FIX_TEMPLATES:
        return FIX_TEMPLATES[source_lower]

    # Partial match
    for key, template in FIX_TEMPLATES.items():
        if key in source_lower or source_lower in key:
            return template

    return None


def get_terraform_alternative(control_id: str, framework: str) -> list[str] | None:
    """Check if a Terraform module exists for this control."""
    import os

    tf_base = os.path.join(os.path.dirname(__file__), "..", "..", "..", "terraform")
    if not os.path.isdir(tf_base):
        return None

    # Map common control areas to terraform module directories
    control_lower = control_id.lower().replace(".", "-")
    # Check aws/modules for matching module
    for provider in ["aws", "azure", "gcp"]:
        provider_dir = os.path.join(tf_base, provider, "modules")
        if os.path.isdir(provider_dir):
            for module in os.listdir(provider_dir):
                if control_lower in module or module in control_lower:
                    module_path = f"terraform/{provider}/modules/{module}"
                    return [
                        f"cd {module_path}",
                        "terraform plan",
                        "terraform apply",
                    ]
    return None
