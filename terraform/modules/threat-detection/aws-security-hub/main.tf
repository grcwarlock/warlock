###############################################################################
# AWS Security Hub Baseline
# Enforces: AU-6 (Audit Review), SI-4 (System Monitoring)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

locals {
  common_tags = merge(var.tags, {
    ManagedBy = "warlock"
    Framework = "NIST-800-53"
  })
}

# -- SI-4: Enable Security Hub account ----------------------------------------

resource "aws_securityhub_account" "main" {}

# -- AU-6/SI-4: CIS AWS Foundations Benchmark ----------------------------------

resource "aws_securityhub_standards_subscription" "cis" {
  count         = var.enable_cis_standard ? 1 : 0
  standards_arn = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.4.0"

  depends_on = [aws_securityhub_account.main]
}

# -- AU-6/SI-4: AWS Foundational Security Best Practices -----------------------

resource "aws_securityhub_standards_subscription" "foundational" {
  count         = var.enable_aws_foundational ? 1 : 0
  standards_arn = "arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0"

  depends_on = [aws_securityhub_account.main]
}

# -- SI-4: Custom action target (optional) ------------------------------------

resource "aws_securityhub_action_target" "warlock" {
  count       = var.create_custom_action ? 1 : 0
  name        = "${var.name_prefix}-warlock-action"
  identifier  = "${var.name_prefix}WarlockAlert"
  description = "Send finding to Warlock GRC platform for remediation tracking"

  depends_on = [aws_securityhub_account.main]
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "threat-detection/aws-security-hub"
  resource_id    = aws_securityhub_account.main.id
  control_ids    = ["AU-6", "SI-4"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    cis_standard_enabled          = tostring(var.enable_cis_standard)
    foundational_standard_enabled = tostring(var.enable_aws_foundational)
  }
}
