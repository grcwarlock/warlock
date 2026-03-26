variable "name_prefix" {
  description = "Prefix applied to all resource names"
  type        = string
  default     = "grc"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "namespaces" {
  description = "List of namespace names to create with Pod Security Standards labels"
  type        = list(string)

  validation {
    condition     = length(var.namespaces) >= 1
    error_message = "At least one namespace must be provided."
  }

  validation {
    condition     = alltrue([for ns in var.namespaces : length(ns) >= 1 && length(ns) <= 63])
    error_message = "Each namespace must be between 1 and 63 characters."
  }
}

variable "enforcement_level" {
  description = "Pod Security Standards enforcement level: restricted, baseline, or privileged"
  type        = string
  default     = "restricted"

  validation {
    condition     = contains(["restricted", "baseline", "privileged"], var.enforcement_level)
    error_message = "enforcement_level must be one of: restricted, baseline, privileged."
  }
}

variable "labels" {
  description = "Labels applied to all resources in this module"
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
