variable "name_prefix" {
  description = "Prefix applied to all resource names in this module"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "connector_name" {
  description = "Name of the SaaS connector (e.g. github, jira, snyk, crowdstrike)"
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,48}[a-z0-9]$", var.connector_name))
    error_message = "connector_name must be lowercase alphanumeric with hyphens, 3-50 characters."
  }
}

variable "secret_backend" {
  description = "Where to store connector secrets: vault, aws_sm, or env"
  type        = string
  default     = "aws_sm"

  validation {
    condition     = contains(["vault", "aws_sm", "env"], var.secret_backend)
    error_message = "secret_backend must be one of: vault, aws_sm, env."
  }
}

variable "secret_data" {
  description = "Map of secret key-value pairs to store (e.g. api_key, client_id, client_secret)"
  type        = map(string)
  default     = {}
  sensitive   = true
}

variable "rotation_days" {
  description = "Number of days between automatic secret rotations"
  type        = number
  default     = 90

  validation {
    condition     = var.rotation_days >= 1 && var.rotation_days <= 365
    error_message = "rotation_days must be between 1 and 365."
  }
}

variable "rotation_lambda_arn" {
  description = "ARN of the Lambda function for AWS Secrets Manager rotation. Null disables auto-rotation."
  type        = string
  default     = null
}

variable "vault_mount_path" {
  description = "Vault KV v2 mount path (only used when secret_backend = vault)"
  type        = string
  default     = "secret"
}

variable "aws_kms_key_arn" {
  description = "ARN of a KMS key for AWS Secrets Manager encryption. Null uses AWS-managed key."
  type        = string
  default     = null
}

variable "tags" {
  description = "Map of tags applied to all resources in this module"
  type        = map(string)
  default     = {}
}

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
