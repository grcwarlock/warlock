###############################################################################
# AWS GuardDuty Organization
# Enforces: SI-3 (Malicious Code Protection), SI-4 (System Monitoring),
#           AU-6 (Audit Review)
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

# -- SI-3: GuardDuty Detector (in delegated admin account) ------------------

resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = var.finding_publishing_frequency
  tags                         = local.common_tags

  datasources {
    s3_logs {
      enable = var.enable_s3_protection
    }
    kubernetes {
      audit_logs {
        enable = var.enable_eks_protection
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = var.enable_malware_protection
        }
      }
    }
  }
}

# -- Delegated admin enrollment ----------------------------------------------

resource "aws_guardduty_organization_admin_account" "delegated" {
  count            = var.organization_admin_account_id != null ? 1 : 0
  admin_account_id = var.organization_admin_account_id
}

# -- SI-4: Auto-enroll new member accounts -----------------------------------

resource "aws_guardduty_organization_configuration" "main" {
  auto_enable_organization_members = var.auto_enable_org_members
  detector_id                      = aws_guardduty_detector.main.id

  datasources {
    s3_logs {
      auto_enable = var.enable_s3_protection
    }
    kubernetes {
      audit_logs {
        enable = var.enable_eks_protection
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          auto_enable = var.enable_malware_protection
        }
      }
    }
  }
}

# -- AU-6: GuardDuty findings -> S3 for central review ----------------------

resource "aws_guardduty_publishing_destination" "s3" {
  count           = var.findings_s3_bucket_arn != null ? 1 : 0
  detector_id     = aws_guardduty_detector.main.id
  destination_arn = var.findings_s3_bucket_arn
  kms_key_arn     = var.findings_kms_key_arn
}

# -- Warlock closed-loop registration ----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "threat-detection/aws-guardduty"
  resource_id    = aws_guardduty_detector.main.id
  control_ids    = ["SI-3", "SI-4", "AU-6"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    detector_id                = aws_guardduty_detector.main.id
    s3_protection_enabled      = tostring(var.enable_s3_protection)
    eks_protection_enabled     = tostring(var.enable_eks_protection)
    malware_protection_enabled = tostring(var.enable_malware_protection)
  }
}
