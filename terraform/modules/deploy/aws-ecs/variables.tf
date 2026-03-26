###############################################################################
# Variables — Warlock AWS ECS Fargate Deployment
###############################################################################

# -- Naming and tagging -------------------------------------------------------

variable "name_prefix" {
  description = "Prefix applied to all resource names"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "environment" {
  description = "Deployment environment (e.g. dev, staging, production)"
  type        = string
  default     = "production"

  validation {
    condition     = contains(["dev", "staging", "production"], var.environment)
    error_message = "environment must be dev, staging, or production."
  }
}

variable "team" {
  description = "Team owning this deployment"
  type        = string
  default     = "platform"
}

variable "tags" {
  description = "Additional tags applied to all resources"
  type        = map(string)
  default     = {}
}

# -- Networking ---------------------------------------------------------------

variable "vpc_id" {
  description = "VPC ID for all resources"
  type        = string
}

variable "public_subnet_ids" {
  description = "Public subnet IDs for the ALB"
  type        = list(string)

  validation {
    condition     = length(var.public_subnet_ids) >= 2
    error_message = "At least 2 public subnets are required for the ALB."
  }
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for ECS tasks, RDS, and ElastiCache"
  type        = list(string)

  validation {
    condition     = length(var.private_subnet_ids) >= 2
    error_message = "At least 2 private subnets are required for high availability."
  }
}

# -- Container ----------------------------------------------------------------

variable "container_image" {
  description = "Docker image URI for the Warlock application (e.g. 123456789.dkr.ecr.us-east-1.amazonaws.com/warlock:latest)"
  type        = string
}

variable "cpu" {
  description = "Fargate task CPU units (1024 = 1 vCPU)"
  type        = number
  default     = 1024

  validation {
    condition     = contains([256, 512, 1024, 2048, 4096], var.cpu)
    error_message = "cpu must be a valid Fargate CPU value: 256, 512, 1024, 2048, or 4096."
  }
}

variable "memory" {
  description = "Fargate task memory in MiB"
  type        = number
  default     = 2048

  validation {
    condition     = var.memory >= 512 && var.memory <= 30720
    error_message = "memory must be between 512 and 30720 MiB."
  }
}

variable "desired_count" {
  description = "Number of ECS tasks to run"
  type        = number
  default     = 2

  validation {
    condition     = var.desired_count >= 1 && var.desired_count <= 20
    error_message = "desired_count must be between 1 and 20."
  }
}

# -- ALB / TLS ----------------------------------------------------------------

variable "certificate_arn" {
  description = "ACM certificate ARN for HTTPS on the ALB"
  type        = string
}

# -- Database -----------------------------------------------------------------

variable "db_instance_class" {
  description = "RDS instance class for PostgreSQL"
  type        = string
  default     = "db.t3.medium"
}

variable "db_name" {
  description = "PostgreSQL database name"
  type        = string
  default     = "warlock"
}

variable "db_username" {
  description = "PostgreSQL master username"
  type        = string
  default     = "warlock"
}

variable "skip_final_snapshot" {
  description = "Skip final RDS snapshot on destroy (set true only for dev/test)"
  type        = bool
  default     = false
}

# -- Logging ------------------------------------------------------------------

variable "log_retention_days" {
  description = "CloudWatch log retention in days (AU-2)"
  type        = number
  default     = 90

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.log_retention_days)
    error_message = "log_retention_days must be a valid CloudWatch Logs retention value."
  }
}

# -- Warlock application config -----------------------------------------------

variable "wlk_jwt_secret" {
  description = "Warlock JWT signing secret (32+ characters)"
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.wlk_jwt_secret) >= 32
    error_message = "wlk_jwt_secret must be at least 32 characters."
  }
}

variable "wlk_ai_enabled" {
  description = "Enable AI-powered compliance assessments"
  type        = string
  default     = "false"

  validation {
    condition     = contains(["true", "false"], var.wlk_ai_enabled)
    error_message = "wlk_ai_enabled must be 'true' or 'false'."
  }
}

variable "wlk_opa_url" {
  description = "OPA server URL for policy evaluation"
  type        = string
  default     = "http://localhost:8181"
}

# -- Warlock closed-loop registration -----------------------------------------

variable "warlock_api_endpoint" {
  description = "Warlock API base URL for self-registration. Null disables registration."
  type        = string
  default     = null
}

variable "warlock_api_token" {
  description = "Bearer token for Warlock API self-registration"
  type        = string
  default     = null
  sensitive   = true
}

variable "warlock_remediation_id" {
  description = "Remediation ID when triggered by closed-loop engine. Null = standalone."
  type        = string
  default     = null
}
