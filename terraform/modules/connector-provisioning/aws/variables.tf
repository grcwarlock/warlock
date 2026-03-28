variable "name_prefix" {
  description = "Prefix applied to all resource names in this module"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "warlock_account_id" {
  description = "AWS account ID where the Warlock platform is deployed (used in trust policy)"
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.warlock_account_id))
    error_message = "warlock_account_id must be a 12-digit AWS account ID."
  }
}

variable "external_id" {
  description = "External ID for the cross-account assume-role condition (prevents confused deputy)"
  type        = string

  validation {
    condition     = length(var.external_id) >= 8
    error_message = "external_id must be at least 8 characters for security."
  }
}

variable "allowed_regions" {
  description = "List of AWS regions the connector role is permitted to access. Empty list allows all regions."
  type        = list(string)
  default     = []
}

variable "connector_names" {
  description = "List of connector names that need SSM SecureString parameters provisioned"
  type        = list(string)
  default     = []
}

variable "kms_deletion_window_days" {
  description = "Number of days before KMS key deletion after scheduling (7-30)"
  type        = number
  default     = 30

  validation {
    condition     = var.kms_deletion_window_days >= 7 && var.kms_deletion_window_days <= 30
    error_message = "kms_deletion_window_days must be between 7 and 30."
  }
}

variable "log_retention_days" {
  description = "Number of days to retain connector audit logs in CloudWatch"
  type        = number
  default     = 90

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
