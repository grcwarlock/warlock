variable "name_prefix" {
  description = "Prefix applied to IAM role and SNS topic names"
  type        = string
  default     = "warlock"

  # T-10: Enforce a non-empty, reasonably sized prefix
  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "auditor_principal_arn" {
  description = "ARN of the principal allowed to assume the audit role (IAM user, role, or assumed-role)"
  type        = string

  # T-10: Validate the ARN format
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
