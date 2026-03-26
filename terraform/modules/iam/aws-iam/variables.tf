variable "name_prefix" {
  description = "Prefix applied to IAM role and SNS topic names"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "auditor_principal_arn" {
  description = "ARN of the principal allowed to assume the audit role (IAM user, role, or assumed-role)"
  type        = string

  validation {
    condition     = startswith(var.auditor_principal_arn, "arn:")
    error_message = "auditor_principal_arn must be a valid ARN starting with 'arn:'."
  }
}

variable "cloudtrail_log_group" {
  description = "CloudWatch log group name for CloudTrail (used by metric filter for root usage alarm)"
  type        = string
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
