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
  description = "IBM Cloud region for the SCC instance"
  type        = string
  default     = "us-south"

  validation {
    condition     = length(var.region) > 0
    error_message = "region must not be empty."
  }
}

variable "resource_group_id" {
  description = "IBM Cloud resource group ID"
  type        = string

  validation {
    condition     = length(var.resource_group_id) > 0
    error_message = "resource_group_id must not be empty."
  }
}

variable "profile_id" {
  description = "ID of the SCC compliance profile to attach (e.g. IBM Cloud Best Practices)"
  type        = string

  validation {
    condition     = length(var.profile_id) > 0
    error_message = "profile_id must not be empty."
  }
}

variable "tags" {
  description = "List of tags applied to all resources in this module"
  type        = list(string)
  default     = []
}

# -- Warlock integration -------------------------------------------------------

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
