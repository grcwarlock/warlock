variable "name_prefix" {
  description = "Prefix applied to all resource names"
  type        = string
  default     = "grc"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "project_id" {
  description = "Scaleway project ID"
  type        = string

  validation {
    condition     = length(var.project_id) > 0
    error_message = "project_id must not be empty."
  }
}

variable "region" {
  description = "Scaleway region (e.g. fr-par, nl-ams, pl-waw)"
  type        = string
  default     = "fr-par"
}

variable "allowed_inbound_ports" {
  description = "List of TCP ports to allow inbound in the security group"
  type        = list(number)
  default     = []

  validation {
    condition     = alltrue([for p in var.allowed_inbound_ports : p >= 1 && p <= 65535])
    error_message = "All ports must be between 1 and 65535."
  }
}

variable "tags" {
  description = "List of tags applied to all resources"
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
