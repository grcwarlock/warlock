variable "name_prefix" {
  description = "Prefix applied to all resource names. Must be 3-10 lowercase alphanumeric characters (Storage Account naming constraint)."
  type        = string
  default     = "warlock"

  validation {
    condition     = can(regex("^[a-z0-9]{3,10}$", var.name_prefix))
    error_message = "name_prefix must be 3-10 lowercase alphanumeric characters (Azure Storage Account naming requires this)."
  }
}

variable "location" {
  description = "Azure region for the storage account (e.g. eastus)"
  type        = string

  validation {
    condition     = length(var.location) > 0
    error_message = "location must not be empty."
  }
}

variable "resource_group_name" {
  description = "Name of the Azure resource group in which the storage account is created"
  type        = string

  validation {
    condition     = length(var.resource_group_name) > 0
    error_message = "resource_group_name must not be empty."
  }
}

variable "allowed_ip_ranges" {
  description = "List of public IP or CIDR ranges allowed to reach the storage account"
  type        = list(string)
  default     = []
}

variable "allowed_subnet_ids" {
  description = "List of Virtual Network subnet IDs allowed to reach the storage account"
  type        = list(string)
  default     = []
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
