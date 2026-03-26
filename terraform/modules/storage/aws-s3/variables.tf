variable "name_prefix" {
  description = "Prefix applied to all resource names"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "bucket_name" {
  description = "Name suffix for the S3 bucket (combined with name_prefix)"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.bucket_name))
    error_message = "bucket_name must be a valid S3 bucket name component (lowercase alphanumeric, hyphens, dots, 3-63 chars)."
  }
}

variable "kms_key_arn" {
  description = "ARN of a KMS key for SSE-KMS encryption. Null uses AES256 (SSE-S3)."
  type        = string
  default     = null
}

variable "enable_access_logging" {
  description = "Enable S3 server access logging to the specified log bucket"
  type        = bool
  default     = false
}

variable "log_bucket_id" {
  description = "Target S3 bucket ID for access logs. Required when enable_access_logging is true."
  type        = string
  default     = null
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
