variable "project_id" {
  description = "GCP project ID where resources will be created"
  type        = string
}

# T-7: Added name_prefix to replace hardcoded "grc_audit_logs" dataset name
variable "name_prefix" {
  description = "Prefix applied to resource names (e.g. BigQuery dataset ID)"
  type        = string
  default     = "grc"

  # T-10: Enforce a non-empty, reasonably sized prefix
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
