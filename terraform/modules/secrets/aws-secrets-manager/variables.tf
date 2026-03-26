variable "name_prefix" {
  description = "Prefix applied to all resource names"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "secret_name" {
  description = "Name suffix for the secret (combined with name_prefix)"
  type        = string

  validation {
    condition     = length(var.secret_name) >= 1 && length(var.secret_name) <= 128
    error_message = "secret_name must be between 1 and 128 characters."
  }
}

variable "kms_key_arn" {
  description = "ARN of a KMS key for secret encryption. Null uses the default AWS-managed key."
  type        = string
  default     = null
}

variable "enable_rotation" {
  description = "Enable automatic secret rotation via Lambda"
  type        = bool
  default     = false
}

variable "rotation_lambda_arn" {
  description = "ARN of the Lambda function for secret rotation. Required when enable_rotation is true."
  type        = string
  default     = null
}

variable "rotation_days" {
  description = "Number of days between automatic rotations (IA-5)"
  type        = number
  default     = 90

  validation {
    condition     = var.rotation_days >= 1 && var.rotation_days <= 365
    error_message = "rotation_days must be between 1 and 365."
  }
}

variable "tags" {
  description = "Map of tags applied to all resources in this module"
  type        = map(string)
  default     = {}
}

variable "warlock_api_endpoint" {
  description = "Warlock API base URL. Null disables self-registration."
  type        = string
  default     = null
}

variable "warlock_api_token" {
  description = "Bearer token for Warlock API."
  type        = string
  default     = null
  sensitive   = true
}

variable "warlock_remediation_id" {
  description = "Remediation ID when triggered by closed-loop engine. Null = standalone."
  type        = string
  default     = null
}
