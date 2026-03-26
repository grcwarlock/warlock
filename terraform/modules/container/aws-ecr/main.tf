###############################################################################
# AWS ECR Repository Hardening Baseline
# Enforces: SC-28 (Encryption at Rest), CM-6 (Image Scanning),
#           SI-3 (Malicious Code Protection)
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

# -- SC-28/CM-6/SI-3: ECR repository with immutable tags and scan-on-push -----

resource "aws_ecr_repository" "main" {
  name                 = var.repository_name
  image_tag_mutability = "IMMUTABLE" # CM-6: prevent tag overwrites
  tags                 = merge(local.common_tags, { Name = "${var.name_prefix}-ecr-${var.repository_name}" })

  image_scanning_configuration {
    scan_on_push = true # SI-3: scan every image on push
  }

  encryption_configuration {
    encryption_type = var.kms_key_arn != null ? "KMS" : "AES256"
    kms_key         = var.kms_key_arn # SC-28: CMEK encryption
  }
}

# -- CM-6: Lifecycle policy — expire untagged, keep last 30 tagged -------------

resource "aws_ecr_lifecycle_policy" "main" {
  repository = aws_ecr_repository.main.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged images after 14 days"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 14
        }
        action = {
          type = "expire"
        }
      },
      {
        rulePriority = 2
        description  = "Keep only the last 30 tagged images"
        selection = {
          tagStatus     = "tagged"
          tagPrefixList = ["v"]
          countType     = "imageCountMoreThan"
          countNumber   = 30
        }
        action = {
          type = "expire"
        }
      },
    ]
  })
}

# -- SC-28: Repository policy for cross-account pull (optional) ----------------

resource "aws_ecr_repository_policy" "cross_account" {
  count      = length(var.cross_account_pull_arns) > 0 ? 1 : 0
  repository = aws_ecr_repository.main.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCrossAccountPull"
        Effect = "Allow"
        Principal = {
          AWS = var.cross_account_pull_arns
        }
        Action = [
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:BatchCheckLayerAvailability",
        ]
      },
    ]
  })
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "container/aws-ecr"
  resource_id    = aws_ecr_repository.main.arn
  control_ids    = ["SC-28", "CM-6", "SI-3"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    image_tag_mutability = "IMMUTABLE"
    scan_on_push         = "true"
    encryption_type      = var.kms_key_arn != null ? "KMS" : "AES256"
  }
}
