variable "name_prefix" {
  description = "Prefix applied to all resource names. Must be 3-10 lowercase alphanumeric characters (Key Vault naming constraint)."
  type        = string
  default     = "warlock"

  validation {
    condition     = can(regex("^[a-z0-9]{3,10}$", var.name_prefix))
    error_message = "name_prefix must be 3-10 lowercase alphanumeric characters (Azure Key Vault naming requires this)."
  }
}

variable "location" {
  description = "Azure region for the Key Vault and supporting resources (e.g. eastus)"
  type        = string

  validation {
    condition     = length(var.location) > 0
    error_message = "location must not be empty."
  }
}

variable "resource_group_name" {
  description = "Name of the Azure resource group in which the Key Vault is created"
  type        = string

  validation {
    condition     = length(var.resource_group_name) > 0
    error_message = "resource_group_name must not be empty."
  }
}

variable "sku_name" {
  description = "Key Vault SKU — 'standard' or 'premium' (premium supports HSM-backed keys)"
  type        = string
  default     = "standard"

  validation {
    condition     = contains(["standard", "premium"], var.sku_name)
    error_message = "sku_name must be 'standard' or 'premium'."
  }
}

variable "soft_delete_retention_days" {
  description = "Days to retain soft-deleted secrets and keys (7-90)"
  type        = number
  default     = 90

  validation {
    condition     = var.soft_delete_retention_days >= 7 && var.soft_delete_retention_days <= 90
    error_message = "soft_delete_retention_days must be between 7 and 90."
  }
}

variable "network_default_action" {
  description = "Default network action when no rules match: 'Deny' (recommended) or 'Allow'"
  type        = string
  default     = "Deny"

  validation {
    condition     = contains(["Allow", "Deny"], var.network_default_action)
    error_message = "network_default_action must be 'Allow' or 'Deny'."
  }
}

variable "allowed_ip_ranges" {
  description = "List of public IP or CIDR ranges allowed to reach the Key Vault"
  type        = list(string)
  default     = []
}

variable "allowed_subnet_ids" {
  description = "List of Virtual Network subnet IDs allowed to reach the Key Vault"
  type        = list(string)
  default     = []
}

variable "log_analytics_workspace_id" {
  description = "Resource ID of a Log Analytics workspace for diagnostic settings. Set to null to skip."
  type        = string
  default     = null
}

variable "private_endpoint_subnet_id" {
  description = "Subnet ID into which a private endpoint for the Key Vault will be provisioned. Set to null to skip."
  type        = string
  default     = null
}

variable "grant_caller_admin" {
  description = "When true, grants the current service principal Key Vault Administrator RBAC role"
  type        = bool
  default     = true
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
