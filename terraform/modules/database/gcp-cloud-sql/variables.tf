variable "project_id" {
  description = "GCP project ID where the Cloud SQL instance will be created"
  type        = string

  validation {
    condition     = length(var.project_id) > 0
    error_message = "project_id must not be empty."
  }
}

variable "name_prefix" {
  description = "Prefix applied to all resource names"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "region" {
  description = "GCP region for the Cloud SQL instance (e.g. us-central1)"
  type        = string

  validation {
    condition     = length(var.region) > 0
    error_message = "region must not be empty."
  }
}

variable "database_version" {
  description = "Cloud SQL database version (e.g. POSTGRES_15, MYSQL_8_0)"
  type        = string
  default     = "POSTGRES_15"

  validation {
    condition     = can(regex("^(POSTGRES|MYSQL|SQLSERVER)_", var.database_version))
    error_message = "database_version must start with POSTGRES_, MYSQL_, or SQLSERVER_."
  }
}

variable "tier" {
  description = "Machine tier for the Cloud SQL instance (e.g. db-f1-micro, db-custom-2-8192)"
  type        = string

  validation {
    condition     = length(var.tier) > 0
    error_message = "tier must not be empty."
  }
}

variable "private_network" {
  description = "Self-link of the VPC network for private IP access"
  type        = string

  validation {
    condition     = length(var.private_network) > 0
    error_message = "private_network must not be empty (Cloud SQL requires VPC-only access)."
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
