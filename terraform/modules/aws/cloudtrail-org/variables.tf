variable "trail_name" {
  description = "Name of the organization CloudTrail trail"
  type        = string
  default     = "warlock-org-trail"

  validation {
    condition     = length(var.trail_name) >= 3 && length(var.trail_name) <= 128
    error_message = "trail_name must be between 3 and 128 characters."
  }
}

variable "trail_bucket_name" {
  description = "Globally unique S3 bucket name to receive organization trail logs"
  type        = string

  validation {
    condition     = length(var.trail_bucket_name) >= 3 && length(var.trail_bucket_name) <= 63
    error_message = "trail_bucket_name must be between 3 and 63 characters (S3 bucket naming constraint)."
  }
}

variable "organization_id" {
  description = "AWS Organizations ID (e.g. o-xxxxxxxxxxxx) — used to grant org-wide S3 write access"
  type        = string

  validation {
    condition     = can(regex("^o-[a-z0-9]{10,32}$", var.organization_id))
    error_message = "organization_id must match the format o-xxxxxxxxxx."
  }
}

variable "kms_key_arn" {
  description = "ARN of a KMS key to encrypt CloudTrail logs and the CloudWatch log group. Set to null to use SSE-S3."
  type        = string
  default     = null
}

variable "log_retention_days" {
  description = "Number of days to retain CloudWatch log group and non-current S3 object versions"
  type        = number
  default     = 365

  validation {
    condition     = var.log_retention_days > 0
    error_message = "log_retention_days must be greater than 0."
  }
}

variable "enable_s3_data_events" {
  description = "Enable CloudTrail data event recording for all S3 objects (AU-12). Significantly increases cost."
  type        = bool
  default     = false
}

variable "enable_lambda_data_events" {
  description = "Enable CloudTrail data event recording for all Lambda functions (AU-12)"
  type        = bool
  default     = false
}

variable "create_sns_topic" {
  description = "When true, create an SNS topic for CloudTrail alerts"
  type        = bool
  default     = false
}

variable "tags" {
  description = "Map of tags applied to all resources in this module"
  type        = map(string)
  default     = {}
}
