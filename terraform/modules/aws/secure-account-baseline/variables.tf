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

# T-1: Optional KMS key ID — if not provided, a managed key is created automatically
variable "kms_key_id" {
  description = "ARN of an existing KMS key for CloudTrail log encryption. If null, a new key with rotation enabled is created."
  type        = string
  default     = null
}

# T-2: Retention period used for S3 non-current version expiration and CloudWatch log group
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
