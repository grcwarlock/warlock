variable "name_prefix" {
  description = "Prefix applied to all resource names"
  type        = string
  default     = "grc"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "region" {
  description = "Scaleway region for object storage (e.g. fr-par, nl-ams)"
  type        = string
  default     = "fr-par"
}

variable "acl" {
  description = "Canned ACL for the bucket (private, public-read, etc.)"
  type        = string
  default     = "private"

  validation {
    condition     = contains(["private", "public-read", "public-read-write", "authenticated-read"], var.acl)
    error_message = "acl must be one of: private, public-read, public-read-write, authenticated-read."
  }
}

variable "enable_object_lock" {
  description = "Enable object lock (GOVERNANCE mode) on the bucket"
  type        = bool
  default     = false
}

variable "object_lock_retention_days" {
  description = "Number of days for object lock retention (when enabled)"
  type        = number
  default     = 90

  validation {
    condition     = var.object_lock_retention_days > 0
    error_message = "object_lock_retention_days must be greater than 0."
  }
}

variable "tags" {
  description = "List of tags in key:value format applied to all resources"
  type        = list(string)
  default     = []
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
