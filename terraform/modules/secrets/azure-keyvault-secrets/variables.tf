variable "key_vault_id" {
  description = "Resource ID of the Azure Key Vault where the secret will be stored"
  type        = string

  validation {
    condition     = length(var.key_vault_id) > 0
    error_message = "key_vault_id must not be empty."
  }
}

variable "secret_name" {
  description = "Name of the Key Vault secret"
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9-]{1,127}$", var.secret_name))
    error_message = "secret_name must be 1-127 alphanumeric characters or hyphens."
  }
}

variable "secret_value" {
  description = "Value of the Key Vault secret"
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.secret_value) > 0
    error_message = "secret_value must not be empty."
  }
}

variable "content_type" {
  description = "Content type of the secret (e.g. 'text/plain', 'application/json')"
  type        = string
  default     = "text/plain"
}

variable "expiration_date" {
  description = "Expiration date of the secret in RFC3339 format (e.g. 2025-12-31T23:59:59Z). Null disables expiration."
  type        = string
  default     = null
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
