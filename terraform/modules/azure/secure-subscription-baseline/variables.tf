variable "name_prefix" {
  description = "Prefix applied to all resource names"
  type        = string
  default     = "grc"

  # T-10: Enforce a non-empty, reasonably sized prefix
  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "resource_group_name" {
  description = "Name of the Azure resource group for security resources"
  type        = string
  default     = "rg-grc-security"
}

variable "location" {
  description = "Azure region for all resources (e.g. eastus, westeurope)"
  type        = string
  default     = "eastus"
}

variable "storage_account_name" {
  description = "Globally unique storage account name (3-24 chars, lowercase alphanumeric only)"
  type        = string

  # T-10: Azure storage account name constraints
  validation {
    condition     = length(var.storage_account_name) >= 3 && length(var.storage_account_name) <= 24 && can(regex("^[a-z0-9]+$", var.storage_account_name))
    error_message = "storage_account_name must be 3-24 characters, lowercase letters and numbers only."
  }
}

variable "log_retention_days" {
  description = "Number of days to retain logs in the Log Analytics workspace"
  type        = number
  default     = 365
}

variable "security_contact_email" {
  description = "Email address for Microsoft Defender for Cloud security alerts"
  type        = string

  # T-10: Require a valid email format (must contain @)
  validation {
    condition     = can(regex("@", var.security_contact_email))
    error_message = "security_contact_email must be a valid email address containing '@'."
  }
}

variable "tags" {
  description = "Map of tags applied to all resources in this module"
  type        = map(string)
  default     = {}
}
