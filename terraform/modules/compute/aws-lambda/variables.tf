variable "name_prefix" {
  description = "Prefix applied to all resource names"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "function_name" {
  description = "Name of the Lambda function (appended to name_prefix)"
  type        = string

  validation {
    condition     = length(var.function_name) >= 1 && length(var.function_name) <= 64
    error_message = "function_name must be between 1 and 64 characters."
  }
}

variable "runtime" {
  description = "Lambda runtime identifier"
  type        = string
  default     = "python3.12"

  validation {
    condition     = length(var.runtime) > 0
    error_message = "runtime must not be empty."
  }
}

variable "handler" {
  description = "Function entrypoint in the format file.method"
  type        = string

  validation {
    condition     = length(var.handler) > 0
    error_message = "handler must not be empty."
  }
}

variable "filename" {
  description = "Path to the Lambda deployment package (.zip)"
  type        = string

  validation {
    condition     = length(var.filename) > 0
    error_message = "filename must not be empty."
  }
}

variable "role_arn" {
  description = "IAM role ARN for the Lambda execution role"
  type        = string

  validation {
    condition     = can(regex("^arn:aws:iam::", var.role_arn))
    error_message = "role_arn must be a valid IAM role ARN."
  }
}

variable "subnet_ids" {
  description = "List of VPC subnet IDs for Lambda VPC placement (SC-7). Empty list disables VPC config."
  type        = list(string)
  default     = []
}

variable "security_group_ids" {
  description = "List of security group IDs when Lambda is VPC-placed. Required when subnet_ids is non-empty."
  type        = list(string)
  default     = []
}

variable "kms_key_arn" {
  description = "KMS key ARN for encrypting environment variables and logs (SC-28). Null uses AWS-managed key."
  type        = string
  default     = null
}

variable "environment_variables" {
  description = "Map of environment variables for the Lambda function"
  type        = map(string)
  default     = {}
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
