###############################################################################
# Warlock Connector Provisioning — AWS
# Provisions IAM role, KMS key, SSM parameters, and CloudWatch log group
# for Warlock connector cross-account access.
# Enforces: AC-2 (Account Management), AC-3 (Access Enforcement),
#           SC-12 (Cryptographic Key Management), AU-3 (Content of Audit Records)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  common_tags = merge(var.tags, {
    managed_by = "warlock"
    component  = "connector-provisioning"
  })
  name_prefix = "${var.name_prefix}-connector"
}

# -- IAM Role for Warlock cross-account access --------------------------------

resource "aws_iam_role" "warlock_connector" {
  name        = "${local.name_prefix}-role"
  description = "Cross-account role for Warlock GRC connector (SecurityAudit + ReadOnly)"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "sts:AssumeRole"
      Principal = {
        AWS = "arn:aws:iam::${var.warlock_account_id}:root"
      }
      Condition = {
        StringEquals = {
          "sts:ExternalId" = var.external_id
        }
      }
    }]
  })

  max_session_duration = 3600
  tags                 = local.common_tags
}

resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.warlock_connector.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "read_only" {
  role       = aws_iam_role.warlock_connector.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# Region restriction policy — limits Warlock to allowed regions only
resource "aws_iam_role_policy" "region_restriction" {
  count = length(var.allowed_regions) > 0 ? 1 : 0
  name  = "${local.name_prefix}-region-restriction"
  role  = aws_iam_role.warlock_connector.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "DenyOutsideAllowedRegions"
      Effect   = "Deny"
      Action   = "*"
      Resource = "*"
      Condition = {
        StringNotEquals = {
          "aws:RequestedRegion" = var.allowed_regions
        }
        # Allow global services (IAM, STS, CloudFront, Route53, etc.)
        "ForAnyValue:StringNotLike" = {
          "aws:PrincipalServiceName" = [
            "iam.amazonaws.com",
            "sts.amazonaws.com",
          ]
        }
      }
    }]
  })
}

# -- KMS key for encrypting connector credentials ----------------------------

resource "aws_kms_key" "connector_credentials" {
  description             = "Encrypts Warlock connector credentials and API keys"
  deletion_window_in_days = var.kms_deletion_window_days
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowAccountAdmin"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowWarlockDecrypt"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.warlock_connector.arn
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
        ]
        Resource = "*"
      },
    ]
  })

  tags = local.common_tags
}

resource "aws_kms_alias" "connector_credentials" {
  name          = "alias/${local.name_prefix}-credentials"
  target_key_id = aws_kms_key.connector_credentials.key_id
}

# -- SSM parameters for storing API keys --------------------------------------

resource "aws_ssm_parameter" "connector_api_key" {
  for_each = toset(var.connector_names)

  name        = "/${var.name_prefix}/connector/${each.value}/api-key"
  description = "API key placeholder for Warlock connector: ${each.value}"
  type        = "SecureString"
  value       = "REPLACE_ME"
  key_id      = aws_kms_key.connector_credentials.key_id

  tags = local.common_tags

  lifecycle {
    ignore_changes = [value]
  }
}

# -- CloudWatch log group for connector audit logs ----------------------------

resource "aws_cloudwatch_log_group" "connector_audit" {
  name              = "/warlock/${var.name_prefix}/connector-audit"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.connector_credentials.arn

  tags = local.common_tags
}

# -- Warlock self-registration ------------------------------------------------

