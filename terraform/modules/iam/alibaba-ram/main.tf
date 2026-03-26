###############################################################################
# Alibaba Cloud RAM Baseline
# Enforces: AC-2 (Account Management), AC-6 (Least Privilege), IA-2 (MFA)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    alicloud = { source = "aliyun/alicloud", version = "~> 1.220" }
  }
}

locals {
  common_tags = merge(var.tags, {
    ManagedBy = "warlock"
    Framework = "NIST-800-53"
  })
}

# -- AC-2/AC-6: Auditor role with least-privilege assume policy --------------

resource "alicloud_ram_role" "auditor" {
  name        = "${var.name_prefix}-auditor"
  description = "Warlock-managed auditor role with read-only access"

  document = jsonencode({
    Version = "1"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          RAM = [for id in var.trusted_account_ids : "acs:ram::${id}:root"]
        }
      }
    ]
  })

  force = true
}

# -- AC-6: Read-only custom policy -------------------------------------------

resource "alicloud_ram_policy" "read_only" {
  policy_name = "${var.name_prefix}-read-only"
  description = "Warlock-managed read-only policy for auditor role"

  policy_document = jsonencode({
    Version = "1"
    Statement = [
      {
        Action = [
          "ecs:Describe*",
          "ecs:List*",
          "rds:Describe*",
          "slb:Describe*",
          "vpc:Describe*",
          "oss:GetBucket*",
          "oss:ListBuckets",
          "kms:Describe*",
          "kms:List*",
          "ram:Get*",
          "ram:List*",
          "actiontrail:Describe*",
          "actiontrail:Get*",
          "actiontrail:List*",
          "log:Get*",
          "log:List*",
          "cms:Describe*",
          "cms:List*",
        ]
        Effect   = "Allow"
        Resource = ["*"]
      }
    ]
  })
}

# -- AC-2: Attach policy to auditor role ------------------------------------

resource "alicloud_ram_role_policy_attachment" "auditor" {
  role_name   = alicloud_ram_role.auditor.name
  policy_name = alicloud_ram_policy.read_only.policy_name
  policy_type = "Custom"
}

# -- IA-2: Account password policy (min 14 chars, require symbols) -----------

resource "alicloud_ram_account_password_policy" "strict" {
  minimum_password_length      = 14
  require_lowercase_characters = true
  require_uppercase_characters = true
  require_numbers              = true
  require_symbols              = true
  max_password_age             = 90
  password_reuse_prevention    = 12
  max_login_attempts           = 5
  hard_expiry                  = false
}

# -- Warlock closed-loop registration ----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "iam/alibaba-ram"
  resource_id    = alicloud_ram_role.auditor.id
  control_ids    = ["AC-2", "AC-6", "IA-2"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    role_name        = alicloud_ram_role.auditor.name
    min_password_len = "14"
    require_symbols  = "true"
    password_max_age = "90"
  }
}
