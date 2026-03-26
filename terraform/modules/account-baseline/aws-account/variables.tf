variable "log_bucket_name" {
  description = "S3 bucket name for audit logs"
  type        = string
}

variable "cloudtrail_name" {
  description = "Name for the CloudTrail trail"
  type        = string
  default     = "warlock-trail"
}

variable "enable_guardduty" {
  description = "Enable GuardDuty threat detection"
  type        = bool
  default     = true
}

variable "enable_security_hub" {
  description = "Enable Security Hub centralized findings"
  type        = bool
  default     = true
}

variable "kms_key_id" {
  description = "ARN of an existing KMS key for CloudTrail log encryption. If null, a new key with rotation enabled is created."
  type        = string
  default     = null
}

variable "log_retention_days" {
  description = "Number of days to retain audit logs (non-current S3 versions and CloudWatch)"
  type        = number
  default     = 365

  validation {
    condition     = var.log_retention_days > 0
    error_message = "log_retention_days must be greater than 0."
  }
}

variable "tags" {
  description = "Common tags for all resources"
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
