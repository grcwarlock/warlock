###############################################################################
# AWS EC2 Instance Hardening
# Enforces: SC-28 (Encrypted EBS), CM-6 (Secure Config), AC-3 (IMDSv2)
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
    ManagedBy = "warlock"
    Framework = "NIST-800-53"
  })
}

# -- SC-28: Enable default EBS encryption for the region -----------------------

resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}

# -- AC-3, CM-6, SC-28: Hardened EC2 instance ---------------------------------

resource "aws_instance" "main" {
  ami           = var.ami_id
  instance_type = var.instance_type
  subnet_id     = var.subnet_id

  vpc_security_group_ids = var.vpc_security_group_ids

  # AC-3: Require IMDSv2 — blocks SSRF-based credential theft
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  # SC-28: Encrypted root volume
  root_block_device {
    encrypted  = true
    kms_key_id = var.kms_key_arn
  }

  # CM-6: Detailed monitoring
  monitoring = true

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-ec2" })
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "compute/aws-ec2"
  resource_id    = aws_instance.main.arn
  control_ids    = ["SC-28", "CM-6", "AC-3"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    imdsv2_required     = "true"
    ebs_encrypted       = "true"
    detailed_monitoring = "true"
  }
}
