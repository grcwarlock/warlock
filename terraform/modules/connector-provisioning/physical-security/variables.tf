variable "name_prefix" {
  description = "Prefix applied to all resource names in this module"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "vendor" {
  description = "Physical security vendor (lenel, genetec, or hid)"
  type        = string

  validation {
    condition     = contains(["lenel", "genetec", "hid"], var.vendor)
    error_message = "vendor must be one of: lenel, genetec, hid."
  }
}

variable "panel_endpoint" {
  description = "IP address or hostname of the access control panel"
  type        = string

  validation {
    condition     = length(var.panel_endpoint) > 0
    error_message = "panel_endpoint must not be empty."
  }
}

variable "api_port" {
  description = "Port number for panel API access. Null uses vendor default (443)."
  type        = number
  default     = null
}

variable "secret_backend" {
  description = "Where to store panel credentials: aws_sm (Secrets Manager) or ssm (SSM Parameter Store)"
  type        = string
  default     = "aws_sm"

  validation {
    condition     = contains(["aws_sm", "ssm"], var.secret_backend)
    error_message = "secret_backend must be one of: aws_sm, ssm."
  }
}

variable "panel_credentials" {
  description = "Map of credential key-value pairs for the panel API (e.g. api_key, username, password)"
  type        = map(string)
  default     = {}
  sensitive   = true
}

variable "vpc_id" {
  description = "VPC ID where the security group is created"
  type        = string

  validation {
    condition     = startswith(var.vpc_id, "vpc-")
    error_message = "vpc_id must start with 'vpc-'."
  }
}

variable "kms_key_arn" {
  description = "ARN of a KMS key for encrypting stored credentials. Null uses AWS-managed key."
  type        = string
  default     = null
}

variable "log_retention_days" {
  description = "Number of days to retain physical security audit logs"
  type        = number
  default     = 365

  validation {
    condition     = var.log_retention_days > 0
    error_message = "log_retention_days must be greater than 0."
  }
}

variable "tags" {
  description = "Map of tags applied to all resources in this module"
  type        = map(string)
  default     = {}
}

variable "warlock_api_endpoint" {
  description = "Warlock API base URL for self-registration. Null disables registration."
  type        = string
  default     = null
}

variable "warlock_api_token" {
  description = "Bearer token for Warlock API self-registration"
  type        = string
  default     = null
  sensitive   = true
}
