variable "name_prefix" {
  description = "Prefix applied to all resource names and tags"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "repository_name" {
  description = "Name of the ECR repository"
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9._/-]*$", var.repository_name))
    error_message = "repository_name must start with a lowercase letter and contain only lowercase alphanumeric, '.', '_', '/', '-'."
  }
}

variable "kms_key_arn" {
  description = "ARN of a KMS key for CMEK encryption. Null uses AES-256 default encryption."
  type        = string
  default     = null
}

variable "cross_account_pull_arns" {
  description = "List of AWS account ARNs allowed to pull images cross-account"
  type        = list(string)
  default     = []
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
