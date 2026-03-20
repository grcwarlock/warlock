###############################################################################
# AWS Config Rules — CIS Managed Rules Pack
# Enforces: CM-2 (Config Recorder), CM-6 (Config Rules), AU-2 (Delivery)
###############################################################################

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  common_tags = merge(var.tags, {
    ManagedBy = "warlock"
    Framework = "NIST-800-53"
  })
}

# ── CM-2: Config Recorder ─────────────────────────────────────────────

resource "aws_iam_role" "config" {
  name = "${var.name_prefix}-config-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
    }]
  })
  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_configuration_recorder" "main" {
  name     = "${var.name_prefix}-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

# ── AU-2: Delivery Channel → S3 + optional SNS ───────────────────────

resource "aws_config_delivery_channel" "main" {
  name           = "${var.name_prefix}-delivery"
  s3_bucket_name = var.config_s3_bucket_name
  s3_key_prefix  = var.config_s3_key_prefix
  sns_topic_arn  = var.config_sns_topic_arn

  snapshot_delivery_properties {
    delivery_frequency = var.delivery_frequency
  }

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.main]
}

# ── CM-6: CIS-aligned Managed Config Rules ────────────────────────────

resource "aws_config_config_rule" "root_mfa_enabled" {
  name        = "${var.name_prefix}-root-mfa-enabled"
  description = "CIS 1.5 — root account MFA must be enabled (IA-2)"

  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_config_rule" "iam_password_policy" {
  name        = "${var.name_prefix}-iam-password-policy"
  description = "CIS 1.8-1.11 — IAM password policy requirements (IA-5)"

  source {
    owner             = "AWS"
    source_identifier = "IAM_PASSWORD_POLICY"
  }

  input_parameters = jsonencode({
    RequireUppercaseCharacters = "true"
    RequireLowercaseCharacters = "true"
    RequireSymbols             = "true"
    RequireNumbers             = "true"
    MinimumPasswordLength      = "14"
    PasswordReusePrevention    = "24"
    MaxPasswordAge             = "90"
  })

  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_config_rule" "access_keys_rotated" {
  name        = "${var.name_prefix}-access-keys-rotated"
  description = "CIS 1.14 — IAM access keys must be rotated within 90 days (IA-5)"

  source {
    owner             = "AWS"
    source_identifier = "ACCESS_KEYS_ROTATED"
  }

  input_parameters = jsonencode({
    maxAccessKeyAge = "90"
  })

  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_config_rule" "s3_bucket_public_read_prohibited" {
  name        = "${var.name_prefix}-s3-no-public-read"
  description = "CIS 2.1.1 — S3 buckets must not allow public read (AC-3)"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_config_rule" "s3_bucket_public_write_prohibited" {
  name        = "${var.name_prefix}-s3-no-public-write"
  description = "CIS 2.1.2 — S3 buckets must not allow public write (AC-3)"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_config_rule" "s3_bucket_server_side_encryption_enabled" {
  name        = "${var.name_prefix}-s3-sse-enabled"
  description = "CIS 2.1.1 — S3 buckets must have SSE enabled (SC-28)"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_config_rule" "cloudtrail_enabled" {
  name        = "${var.name_prefix}-cloudtrail-enabled"
  description = "CIS 3.1 — CloudTrail must be enabled in all regions (AU-2)"

  source {
    owner             = "AWS"
    source_identifier = "MULTI_REGION_CLOUDTRAIL_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_config_rule" "cloudtrail_log_file_validation" {
  name        = "${var.name_prefix}-cloudtrail-log-validation"
  description = "CIS 3.2 — CloudTrail log file validation must be enabled (AU-9)"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_config_rule" "encrypted_volumes" {
  name        = "${var.name_prefix}-ebs-encrypted"
  description = "CIS 2.2.1 — EBS volumes must be encrypted (SC-28)"

  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_config_rule" "rds_storage_encrypted" {
  name        = "${var.name_prefix}-rds-encrypted"
  description = "CIS 2.3.1 — RDS storage must be encrypted (SC-28)"

  source {
    owner             = "AWS"
    source_identifier = "RDS_STORAGE_ENCRYPTED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_config_rule" "kms_cmk_not_scheduled_for_deletion" {
  name        = "${var.name_prefix}-kms-no-deletion"
  description = "CIS 3.8 — KMS CMKs must not be scheduled for deletion (SC-12)"

  source {
    owner             = "AWS"
    source_identifier = "KMS_CMK_NOT_SCHEDULED_FOR_DELETION"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_config_rule" "restricted_ssh" {
  name        = "${var.name_prefix}-restricted-ssh"
  description = "CIS 4.1 — Security groups must not allow unrestricted SSH (SC-7)"

  source {
    owner             = "AWS"
    source_identifier = "RESTRICTED_INCOMING_TRAFFIC"
  }

  input_parameters = jsonencode({
    blockedPort1 = "22"
  })

  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_config_rule" "restricted_rdp" {
  name        = "${var.name_prefix}-restricted-rdp"
  description = "CIS 4.2 — Security groups must not allow unrestricted RDP (SC-7)"

  source {
    owner             = "AWS"
    source_identifier = "RESTRICTED_INCOMING_TRAFFIC"
  }

  input_parameters = jsonencode({
    blockedPort1 = "3389"
  })

  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_config_rule" "vpc_flow_logs_enabled" {
  name        = "${var.name_prefix}-vpc-flow-logs"
  description = "CIS 3.9 — VPC flow logs must be enabled (AU-2)"

  source {
    owner             = "AWS"
    source_identifier = "VPC_FLOW_LOGS_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_config_rule" "guardduty_enabled_centralized" {
  name        = "${var.name_prefix}-guardduty-enabled"
  description = "CIS 3.13 — GuardDuty must be enabled (SI-3)"

  source {
    owner             = "AWS"
    source_identifier = "GUARDDUTY_ENABLED_CENTRALIZED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
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

  triggers_replace = [aws_config_configuration_recorder.main.id]

  provisioner "local-exec" {
    command = <<-EOT
      curl -sf -X POST "${var.warlock_api_endpoint}/api/v1/evidence" \
        -H "Authorization: Bearer ${var.warlock_api_token}" \
        -H "Content-Type: application/json" \
        -d '{
          "module": "aws/config-rules",
          "resource_id": "${aws_config_configuration_recorder.main.id}",
          "control_ids": ["CM-2", "CM-6", "AU-2"],
          "attributes": {
            "recorder_name": "${aws_config_configuration_recorder.main.name}",
            "rules_count": 15,
            "cis_managed_rules": true
          }
        }' || true
    EOT
  }
}
