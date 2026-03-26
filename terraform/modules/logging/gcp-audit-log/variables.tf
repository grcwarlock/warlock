variable "project_id" {
  description = "GCP project ID where audit logging will be configured"
  type        = string

  validation {
    condition     = length(var.project_id) > 0
    error_message = "project_id must not be empty."
  }
}

variable "name_prefix" {
  description = "Prefix applied to the sink, dataset, and other resources"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "region" {
  description = "GCP region for the BigQuery dataset (e.g. us-central1, EU)"
  type        = string

  validation {
    condition     = length(var.region) > 0
    error_message = "region must not be empty."
  }
}

variable "log_retention_days" {
  description = "Number of days to retain audit logs in BigQuery (30-3650)"
  type        = number
  default     = 365

  validation {
    condition     = var.log_retention_days >= 30 && var.log_retention_days <= 3650
    error_message = "log_retention_days must be between 30 and 3650."
  }
}

variable "labels" {
  description = "Map of GCP labels applied to all resources in this module"
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
