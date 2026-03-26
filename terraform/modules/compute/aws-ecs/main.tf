###############################################################################
# AWS ECS Cluster Hardening
# Enforces: AC-3 (Task Role Least Privilege), SC-7 (Network Mode awsvpc),
#           AU-2 (Logging)
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

# -- AU-2: CloudWatch log group for container logs ----------------------------

resource "aws_cloudwatch_log_group" "ecs" {
  name              = "/ecs/${var.name_prefix}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-ecs-logs" })
}

# -- AC-3, AU-2: ECS cluster with execute command logging ---------------------

resource "aws_ecs_cluster" "main" {
  name = "${var.name_prefix}-cluster"

  setting {
    name  = "containerInsights"
    value = var.enable_container_insights ? "enabled" : "disabled"
  }

  configuration {
    execute_command_configuration {
      logging = "OVERRIDE"

      log_configuration {
        cloud_watch_log_group_name = aws_cloudwatch_log_group.ecs.name
      }
    }
  }

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-ecs-cluster" })
}

# -- SC-7: Fargate capacity provider (enforces awsvpc network mode) -----------

resource "aws_ecs_cluster_capacity_providers" "main" {
  cluster_name = aws_ecs_cluster.main.name

  capacity_providers = ["FARGATE"]

  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
    base              = 0
  }
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "compute/aws-ecs"
  resource_id    = aws_ecs_cluster.main.arn
  control_ids    = ["AC-3", "SC-7", "AU-2"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    container_insights = tostring(var.enable_container_insights)
    capacity_provider  = "FARGATE"
    log_retention_days = tostring(var.log_retention_days)
  }
}
