###############################################################################
# Warlock Connector Provisioning — SaaS
# Generic SaaS connector credential management with Vault or AWS Secrets
# Manager backend and automated rotation schedules.
# Enforces: SC-12 (Cryptographic Key Management), SC-28 (Protection at Rest),
#           IA-5 (Authenticator Management)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
      # Only required when secret_backend = "aws_sm"
      configuration_aliases = [aws]
    }
    vault = {
      source  = "hashicorp/vault"
      version = "~> 4.0"
      # Only required when secret_backend = "vault"
      configuration_aliases = [vault]
    }
  }
}

locals {
  common_tags = merge(var.tags, {
    managed_by = "warlock"
    component  = "connector-provisioning"
  })

  use_vault  = var.secret_backend == "vault"
  use_aws_sm = var.secret_backend == "aws_sm"

  secret_path = local.use_vault ? (
    length(vault_kv_secret_v2.connector) > 0 ? vault_kv_secret_v2.connector[0].path : ""
    ) : local.use_aws_sm ? (
    length(aws_secretsmanager_secret.connector) > 0 ? aws_secretsmanager_secret.connector[0].name : ""
  ) : "env://${upper(replace(var.connector_name, "-", "_"))}_API_KEY"
}

# -- Vault backend ------------------------------------------------------------

resource "vault_kv_secret_v2" "connector" {
  count = local.use_vault ? 1 : 0

  mount = var.vault_mount_path
  name  = "warlock/connectors/${var.connector_name}"

  data_json = jsonencode(var.secret_data)

  custom_metadata {
    max_versions = 10
    data = {
      managed_by     = "warlock"
      connector_name = var.connector_name
      component      = "connector-provisioning"
    }
  }
}

# Vault policy for Warlock to read connector secrets
resource "vault_policy" "connector_read" {
  count = local.use_vault ? 1 : 0

  name = "warlock-connector-${var.connector_name}-read"

  policy = <<-EOT
    path "${var.vault_mount_path}/data/warlock/connectors/${var.connector_name}" {
      capabilities = ["read"]
    }
    path "${var.vault_mount_path}/metadata/warlock/connectors/${var.connector_name}" {
      capabilities = ["read"]
    }
  EOT
}

# -- AWS Secrets Manager backend ----------------------------------------------

resource "aws_secretsmanager_secret" "connector" {
  count = local.use_aws_sm ? 1 : 0

  name        = "${var.name_prefix}/connector/${var.connector_name}"
  description = "Warlock connector credentials for ${var.connector_name}"
  kms_key_id  = var.aws_kms_key_arn

  tags = local.common_tags
}

resource "aws_secretsmanager_secret_version" "connector" {
  count = local.use_aws_sm ? 1 : 0

  secret_id     = aws_secretsmanager_secret.connector[0].id
  secret_string = jsonencode(var.secret_data)
}

# Rotation schedule for AWS Secrets Manager
resource "aws_secretsmanager_secret_rotation" "connector" {
  count = local.use_aws_sm && var.rotation_lambda_arn != null ? 1 : 0

  secret_id           = aws_secretsmanager_secret.connector[0].id
  rotation_lambda_arn = var.rotation_lambda_arn

  rotation_rules {
    automatically_after_days = var.rotation_days
  }
}

# -- Warlock self-registration ------------------------------------------------

