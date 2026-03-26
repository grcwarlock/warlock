variable "name_prefix" {
  description = "Prefix applied to all resource names"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "location" {
  description = "Azure region for all resources (e.g. eastus)"
  type        = string

  validation {
    condition     = length(var.location) > 0
    error_message = "location must not be empty."
  }
}

variable "resource_group_name" {
  description = "Name of the Azure resource group"
  type        = string

  validation {
    condition     = length(var.resource_group_name) > 0
    error_message = "resource_group_name must not be empty."
  }
}

variable "storage_account_name" {
  description = "Name of the storage account backing the Function App"
  type        = string

  validation {
    condition     = length(var.storage_account_name) > 0
    error_message = "storage_account_name must not be empty."
  }
}

variable "storage_account_access_key" {
  description = "Access key for the storage account"
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.storage_account_access_key) > 0
    error_message = "storage_account_access_key must not be empty."
  }
}

variable "sku_name" {
  description = "SKU for the App Service plan (e.g. Y1 for consumption, B1 for basic)"
  type        = string
  default     = "Y1"

  validation {
    condition     = length(var.sku_name) > 0
    error_message = "sku_name must not be empty."
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
