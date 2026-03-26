###############################################################################
# AWS Secrets Manager — Secrets Rotation
# Enforces: SC-12 (Key Management), IA-5 (Authenticator Management)
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

# -- SC-12/IA-5: Secret with recovery window and optional KMS ------------------

resource "aws_secretsmanager_secret" "main" {
  name                    = "${var.name_prefix}-${var.secret_name}"
  kms_key_id              = var.kms_key_arn
  recovery_window_in_days = 30 # SC-12: prevent permanent loss

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-${var.secret_name}" })
}

# -- IA-5: Automatic rotation (optional) --------------------------------------

resource "aws_secretsmanager_secret_rotation" "main" {
  count = var.enable_rotation ? 1 : 0

  secret_id           = aws_secretsmanager_secret.main.id
  rotation_lambda_arn = var.rotation_lambda_arn

  rotation_rules {
    automatically_after_days = var.rotation_days # IA-5: enforce rotation schedule
  }
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "secrets/aws-secrets-manager"
  resource_id    = aws_secretsmanager_secret.main.arn
  control_ids    = ["SC-12", "IA-5"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    recovery_window_days = "30"
    rotation_enabled     = tostring(var.enable_rotation)
    rotation_days        = tostring(var.rotation_days)
    kms_encrypted        = tostring(var.kms_key_arn != null)
  }
}
