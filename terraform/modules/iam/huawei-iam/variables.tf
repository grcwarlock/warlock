variable "name_prefix" {
  description = "Prefix applied to IAM groups, roles, and related resources"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "domain_id" {
  description = "Huawei Cloud IAM domain ID for role assignment scope"
  type        = string

  validation {
    condition     = length(var.domain_id) > 0
    error_message = "domain_id must not be empty."
  }
}

variable "auditor_users" {
  description = "List of IAM user IDs to add to the auditor group"
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Map of tags applied to all taggable resources in this module"
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
