variable "project_id" {
  description = "GCP project ID where resources will be created"
  type        = string
}

variable "name_prefix" {
  description = "Prefix applied to resource names (e.g. BigQuery dataset ID)"
  type        = string
  default     = "grc"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "region" {
  description = "GCP region for regional resources (e.g. us-central1)"
  type        = string
  default     = "us-central1"
}

variable "log_retention_days" {
  description = "Number of days before BigQuery audit log table records expire"
  type        = number
  default     = 365
}

variable "labels" {
  description = "Map of GCP labels applied to all resources"
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
