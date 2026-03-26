variable "name_prefix" {
  description = "Prefix applied to Container Registry instance and namespace"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "instance_type" {
  description = "Container Registry Enterprise Edition instance type (Basic, Standard, Advanced)"
  type        = string
  default     = "Basic"

  validation {
    condition     = contains(["Basic", "Standard", "Advanced"], var.instance_type)
    error_message = "instance_type must be one of: Basic, Standard, Advanced."
  }
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
