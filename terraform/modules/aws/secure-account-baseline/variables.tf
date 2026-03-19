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

variable "tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default     = {}
}
