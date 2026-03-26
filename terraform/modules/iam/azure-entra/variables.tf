variable "name_prefix" {
  description = "Prefix applied to all resource names. Must be 3-24 lowercase alphanumeric characters or hyphens."
  type        = string
  default     = "warlock"

  validation {
    condition     = can(regex("^[a-z0-9-]{3,24}$", var.name_prefix))
    error_message = "name_prefix must be 3-24 lowercase alphanumeric characters or hyphens."
  }
}

variable "location" {
  description = "Azure region for the managed identity (e.g. eastus)"
  type        = string

  validation {
    condition     = length(var.location) > 0
    error_message = "location must not be empty."
  }
}

variable "resource_group_name" {
  description = "Name of the Azure resource group for the managed identity"
  type        = string

  validation {
    condition     = length(var.resource_group_name) > 0
    error_message = "resource_group_name must not be empty."
  }
}

variable "group_display_name" {
  description = "Display name for the Azure AD security group used for RBAC"
  type        = string

  validation {
    condition     = length(var.group_display_name) > 0
    error_message = "group_display_name must not be empty."
  }
}

variable "group_members" {
  description = "List of Azure AD object IDs to add as members of the security group"
  type        = list(string)
  default     = []
}

variable "enable_conditional_access_mfa" {
  description = "Create a Conditional Access policy requiring MFA for group members. Requires Azure AD P1 license."
  type        = bool
  default     = false
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
