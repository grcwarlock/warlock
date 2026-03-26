variable "name_prefix" {
  description = "Prefix applied to all resource names"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "key_vault_id" {
  description = "Resource ID of the Azure Key Vault where the certificate is stored"
  type        = string

  validation {
    condition     = length(var.key_vault_id) > 0
    error_message = "key_vault_id must not be empty."
  }
}

variable "certificate_name" {
  description = "Name of the certificate in Key Vault"
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9-]+$", var.certificate_name))
    error_message = "certificate_name must contain only alphanumeric characters and hyphens."
  }
}

variable "common_name" {
  description = "Common name (CN) for the self-signed certificate subject"
  type        = string

  validation {
    condition     = length(var.common_name) > 0
    error_message = "common_name must not be empty."
  }
}

variable "validity_in_months" {
  description = "Validity period of the certificate in months"
  type        = number
  default     = 12

  validation {
    condition     = var.validity_in_months >= 1 && var.validity_in_months <= 120
    error_message = "validity_in_months must be between 1 and 120."
  }
}

variable "tags" {
  description = "Map of tags applied to all resources in this module"
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
