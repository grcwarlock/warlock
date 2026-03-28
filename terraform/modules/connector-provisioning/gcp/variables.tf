variable "name_prefix" {
  description = "Prefix applied to all resource names in this module"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "project_id" {
  description = "GCP project ID where connector resources are provisioned"
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a valid GCP project ID (6-30 lowercase letters, digits, hyphens)."
  }
}

variable "warlock_pool_id" {
  description = "Existing workload identity pool ID to use instead of creating a new one"
  type        = string
  default     = null
}

variable "create_workload_identity_pool" {
  description = "Whether to create a new workload identity pool for Warlock. Set to false if using warlock_pool_id."
  type        = bool
  default     = true
}

variable "warlock_aws_account_id" {
  description = "AWS account ID for workload identity federation (if Warlock runs in AWS). Null skips AWS provider."
  type        = string
  default     = null
}

variable "warlock_oidc_issuer" {
  description = "OIDC issuer URI for workload identity federation. Null skips OIDC provider."
  type        = string
  default     = null
}

variable "connector_names" {
  description = "List of connector names that need Secret Manager entries provisioned"
  type        = list(string)
  default     = []
}

variable "labels" {
  description = "Map of labels applied to all GCP resources in this module"
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
