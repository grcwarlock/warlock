variable "name_prefix" {
  description = "Prefix applied to all resource names in this module"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "subscription_id" {
  description = "Azure subscription ID to grant Warlock Reader access"
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", var.subscription_id))
    error_message = "subscription_id must be a valid UUID."
  }
}

variable "warlock_app_id" {
  description = "Application (client) ID of the Warlock platform in Azure AD (for future federation)"
  type        = string
  default     = null
}

variable "location" {
  description = "Azure region for the resource group and Key Vault"
  type        = string
  default     = "eastus"
}

variable "create_client_secret" {
  description = "Whether to create a client secret for the service principal. Set to false if using federated credentials."
  type        = bool
  default     = true
}

variable "client_secret_end_date" {
  description = "Expiration date for the client secret (RFC3339 format)"
  type        = string
  default     = "2027-01-01T00:00:00Z"
}

variable "log_analytics_workspace_id" {
  description = "Resource ID of a Log Analytics workspace for diagnostic log export"
  type        = string
  default     = null
}

variable "tags" {
  description = "Map of tags applied to all resources in this module"
  type        = map(string)
  default     = {}
}

variable "warlock_api_endpoint" {
  description = "Warlock API base URL for self-registration. Null disables registration."
  type        = string
  default     = null
}

variable "warlock_api_token" {
  description = "Bearer token for Warlock API self-registration"
  type        = string
  default     = null
  sensitive   = true
}
