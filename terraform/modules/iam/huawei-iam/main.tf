###############################################################################
# Huawei Cloud IAM Baseline
# Enforces: AC-2 (Account Management), AC-6 (Least Privilege)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    huaweicloud = { source = "huaweicloud/huaweicloud", version = "~> 1.60" }
  }
}

locals {
  common_tags = merge(var.tags, {
    ManagedBy = "warlock"
    Framework = "NIST-800-53"
  })
}

# -- AC-2: IAM group for auditors -------------------------------------------

resource "huaweicloud_identity_group" "auditor" {
  name        = "${var.name_prefix}-auditor"
  description = "Warlock-managed auditor group with read-only access"
}

# -- AC-6: Custom read-only auditor role ------------------------------------

resource "huaweicloud_identity_role" "auditor" {
  name        = "${var.name_prefix}-auditor-role"
  description = "Warlock-managed read-only role for auditor group"
  type        = "AX"

  policy = jsonencode({
    Version = "1.1"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecs:*:get*",
          "ecs:*:list*",
          "evs:*:get*",
          "evs:*:list*",
          "vpc:*:get*",
          "vpc:*:list*",
          "obs:bucket:Get*",
          "obs:bucket:List*",
          "obs:object:Get*",
          "kms:cmk:get*",
          "kms:cmk:list*",
          "iam:*:get*",
          "iam:*:list*",
          "cts:tracker:get*",
          "cts:trace:list*",
          "ces:*:get*",
          "ces:*:list*",
          "hss:*:get*",
          "hss:*:list*",
        ]
      }
    ]
  })
}

# -- AC-2: Assign auditor role to auditor group ------------------------------

resource "huaweicloud_identity_group_role_assignment" "auditor" {
  group_id  = huaweicloud_identity_group.auditor.id
  role_id   = huaweicloud_identity_role.auditor.id
  domain_id = var.domain_id
}

# -- AC-2: Password policy --------------------------------------------------

resource "huaweicloud_identity_password_policy" "strict" {
  password_char_combination             = 4
  minimum_password_length               = 14
  number_of_recent_passwords_disallowed = 12
  password_validity_period              = 90
  maximum_consecutive_identical_chars   = 3
  minimum_password_age                  = 0
}

# -- Warlock closed-loop registration ----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "iam/huawei-iam"
  resource_id    = huaweicloud_identity_group.auditor.id
  control_ids    = ["AC-2", "AC-6"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    group_name       = huaweicloud_identity_group.auditor.name
    role_name        = huaweicloud_identity_role.auditor.name
    min_password_len = "14"
  }
}
