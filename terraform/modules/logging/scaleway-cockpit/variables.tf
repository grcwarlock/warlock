variable "name_prefix" {
  description = "Prefix applied to all resource names"
  type        = string
  default     = "grc"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "project_id" {
  description = "Scaleway project ID"
  type        = string

  validation {
    condition     = length(var.project_id) > 0
    error_message = "project_id must not be empty."
  }
}

variable "grafana_admin_login" {
  description = "Login for the Grafana admin user. Null skips Grafana user creation."
  type        = string
  default     = null
}

variable "enable_log_source" {
  description = "Whether to create a Cockpit log data source"
  type        = bool
  default     = false
}

variable "log_retention_days" {
  description = "Number of days to retain logs in the Cockpit data source"
  type        = number
  default     = 365

  validation {
    condition     = var.log_retention_days > 0
    error_message = "log_retention_days must be greater than 0."
  }
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
