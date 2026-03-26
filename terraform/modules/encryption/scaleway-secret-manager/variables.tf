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

variable "secret_name" {
  description = "Name of the secret (will be prefixed with name_prefix)"
  type        = string

  validation {
    condition     = length(var.secret_name) > 0
    error_message = "secret_name must not be empty."
  }
}

variable "secret_data" {
  description = "The sensitive data to store in the secret"
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.secret_data) > 0
    error_message = "secret_data must not be empty."
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
