###############################################################################
# IAM Baseline — Enforces AC-2, AC-6
###############################################################################

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

locals {
  common_tags = merge(var.tags, { ManagedBy = "warlock" })
}

# ── Warlock Audit Role (read-only) ────────────────────────────────────

resource "aws_iam_role" "grc_auditor" {
  # T-7: Use name_prefix variable instead of hardcoded "warlock-auditor"
  name = "${var.name_prefix}-auditor"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = var.auditor_principal_arn }
      Action    = "sts:AssumeRole"
      Condition = { Bool = { "aws:MultiFactorAuthPresent" = "true" } }
    }]
  })
  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "auditor_security_audit" {
  role       = aws_iam_role.grc_auditor.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

# ── MFA Enforcement Policy ───────────────────────────────────────────

resource "aws_iam_policy" "require_mfa" {
  name        = "RequireMFAForConsole"
  description = "Deny console access without MFA (AC-2, IA-2)"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowViewAccountInfo"
        Effect   = "Allow"
        Action   = ["iam:ListVirtualMFADevices", "iam:GetAccountPasswordPolicy"]
        Resource = "*"
      },
      {
        Sid    = "AllowManageOwnMFA"
        Effect = "Allow"
        Action = ["iam:CreateVirtualMFADevice", "iam:EnableMFADevice", "iam:ResyncMFADevice"]
        Resource = [
          "arn:aws:iam::*:mfa/$${aws:username}",
          "arn:aws:iam::*:user/$${aws:username}"
        ]
      },
      {
        Sid       = "DenyAllExceptMFASetup"
        Effect    = "Deny"
        NotAction = ["iam:CreateVirtualMFADevice", "iam:EnableMFADevice", "iam:ListMFADevices", "iam:ListVirtualMFADevices", "iam:ResyncMFADevice", "sts:GetSessionToken"]
        Resource  = "*"
        Condition = { BoolIfExists = { "aws:MultiFactorAuthPresent" = "false" } }
      },
    ]
  })
  tags = local.common_tags
}

# ── Root Account Usage Alarm ─────────────────────────────────────────

resource "aws_sns_topic" "security_alerts" {
  # T-7: Use name_prefix variable instead of hardcoded "grc-security-alerts"
  name = "${var.name_prefix}-security-alerts"
  tags = local.common_tags
}

resource "aws_cloudwatch_log_metric_filter" "root_usage" {
  name           = "RootAccountUsage"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
  metric_transformation {
    name      = "RootAccountUsageCount"
    namespace = "GRCToolkit/Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "root_usage" {
  alarm_name          = "RootAccountUsage"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "RootAccountUsageCount"
  namespace           = "GRCToolkit/Security"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Root account usage detected (AC-6)"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  tags                = local.common_tags
}

# ── #41: Warlock self-registration evidence ───────────────────────────

variable "warlock_api_endpoint" {
  description = "Warlock API base URL for self-registration evidence. Set to null to disable."
  type        = string
  default     = null
}

variable "warlock_api_token" {
  description = "Bearer token for Warlock API authentication."
  type        = string
  default     = null
  sensitive   = true
}

resource "terraform_data" "warlock_evidence" {
  count = var.warlock_api_endpoint != null ? 1 : 0

  triggers_replace = [aws_iam_role.grc_auditor.arn]

  provisioner "local-exec" {
    command = <<-EOT
      curl -sf -X POST "${var.warlock_api_endpoint}/api/v1/evidence" \
        -H "Authorization: Bearer ${var.warlock_api_token}" \
        -H "Content-Type: application/json" \
        -d '{
          "module": "aws/iam-baseline",
          "resource_id": "${aws_iam_role.grc_auditor.arn}",
          "control_ids": ["AC-2", "AC-6", "IA-2"],
          "attributes": {
            "auditor_role_name": "${aws_iam_role.grc_auditor.name}",
            "mfa_enforcement_policy": "RequireMFAForConsole",
            "root_usage_alarm": "RootAccountUsage"
          }
        }' || true
    EOT
  }
}
