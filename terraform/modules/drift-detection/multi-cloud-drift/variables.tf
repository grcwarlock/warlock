variable "name_prefix" {
  description = "Prefix applied to all resource names in this module"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "state_bucket_name" {
  description = "Name of the S3 bucket containing the Terraform state files"
  type        = string

  validation {
    condition     = length(var.state_bucket_name) > 0
    error_message = "state_bucket_name must not be empty."
  }
}

variable "state_bucket_arn" {
  description = "ARN of the S3 bucket containing the Terraform state files (for IAM policy)"
  type        = string

  validation {
    condition     = startswith(var.state_bucket_arn, "arn:aws:s3:::")
    error_message = "state_bucket_arn must be a valid S3 ARN (arn:aws:s3:::bucket-name)."
  }
}

variable "state_keys" {
  description = "List of S3 object keys for Terraform state files to monitor (e.g. [\"env/prod/terraform.tfstate\", \"env/staging/terraform.tfstate\"])"
  type        = list(string)

  validation {
    condition     = length(var.state_keys) > 0
    error_message = "state_keys must contain at least one state file key."
  }

  validation {
    condition     = alltrue([for k in var.state_keys : length(k) > 0])
    error_message = "Each state key must be a non-empty string."
  }
}

variable "schedule_expression" {
  description = "EventBridge cron or rate expression for drift detection runs (e.g. rate(1 hour), cron(0 */6 * * ? *))"
  type        = string
  default     = "rate(1 hour)"

  validation {
    condition     = can(regex("^(rate|cron)\\(", var.schedule_expression))
    error_message = "schedule_expression must start with 'rate(' or 'cron('."
  }
}

variable "lambda_timeout_seconds" {
  description = "Maximum Lambda execution time in seconds"
  type        = number
  default     = 300

  validation {
    condition     = var.lambda_timeout_seconds >= 30 && var.lambda_timeout_seconds <= 900
    error_message = "lambda_timeout_seconds must be between 30 and 900."
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
  description = "ARN of a KMS key used to encrypt Lambda environment variables, SSM parameter, and CloudWatch logs. Set to null to use AWS-managed encryption."
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
  description = "Bearer token for Warlock API. Stored in SSM SecureString."
  type        = string
  sensitive   = true
}

variable "warlock_remediation_id" {
  description = "Remediation ID when triggered by closed-loop engine. Null = standalone."
  type        = string
  default     = null
}
