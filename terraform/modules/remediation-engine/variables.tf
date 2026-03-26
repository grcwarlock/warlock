variable "name_prefix" {
  description = "Prefix applied to all resource names in this module"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "tfc_org" {
  description = "Terraform Cloud organization name"
  type        = string

  validation {
    condition     = length(var.tfc_org) > 0
    error_message = "tfc_org must not be empty."
  }
}

variable "tfc_token" {
  description = "Terraform Cloud API token (stored in SSM SecureString, never in env vars)"
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.tfc_token) > 0
    error_message = "tfc_token must not be empty."
  }
}

variable "lambda_timeout_seconds" {
  description = "Maximum Lambda execution time in seconds"
  type        = number
  default     = 300

  validation {
    condition     = var.lambda_timeout_seconds >= 60 && var.lambda_timeout_seconds <= 900
    error_message = "lambda_timeout_seconds must be between 60 and 900."
  }
}

variable "log_retention_days" {
  description = "Number of days to retain Lambda CloudWatch logs"
  type        = number
  default     = 90

  validation {
    condition     = var.log_retention_days > 0
    error_message = "log_retention_days must be greater than 0."
  }
}

variable "kms_key_arn" {
  description = "ARN of a KMS key used to encrypt SSM parameters, Lambda environment variables, and CloudWatch logs. Set to null to use AWS-managed encryption."
  type        = string
  default     = null
}

variable "tags" {
  description = "Map of tags applied to all resources in this module"
  type        = map(string)
  default     = {}
}

variable "warlock_api_endpoint" {
  description = "Warlock API base URL (e.g. https://warlock.example.com). Null disables self-registration."
  type        = string
  default     = null
}

variable "warlock_api_token" {
  description = "Bearer token for Warlock API"
  type        = string
  default     = null
  sensitive   = true
}

variable "warlock_remediation_id" {
  description = "Remediation ID when triggered by closed-loop engine. Null = standalone."
  type        = string
  default     = null
}
