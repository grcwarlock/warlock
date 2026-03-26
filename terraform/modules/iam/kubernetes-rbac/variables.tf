variable "name_prefix" {
  description = "Prefix applied to all resource names"
  type        = string
  default     = "grc"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "subjects" {
  description = "List of subjects to bind to the auditor ClusterRole"
  type = list(object({
    kind      = string
    name      = string
    namespace = optional(string)
  }))

  validation {
    condition     = length(var.subjects) >= 1
    error_message = "At least one subject must be provided."
  }

  validation {
    condition     = alltrue([for s in var.subjects : contains(["User", "Group", "ServiceAccount"], s.kind)])
    error_message = "Subject kind must be one of: User, Group, ServiceAccount."
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
