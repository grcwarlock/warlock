variable "name_prefix" {
  description = "Prefix applied to all resource names. Must be 3-10 lowercase alphanumeric characters."
  type        = string
  default     = "warlock"

  validation {
    condition     = can(regex("^[a-z0-9]{3,10}$", var.name_prefix))
    error_message = "name_prefix must be 3-10 lowercase alphanumeric characters."
  }
}

variable "location" {
  description = "Azure region for the SQL server and database (e.g. eastus)"
  type        = string

  validation {
    condition     = length(var.location) > 0
    error_message = "location must not be empty."
  }
}

variable "resource_group_name" {
  description = "Name of the Azure resource group in which the SQL server is created"
  type        = string

  validation {
    condition     = length(var.resource_group_name) > 0
    error_message = "resource_group_name must not be empty."
  }
}

variable "administrator_login" {
  description = "Administrator login name for the SQL server"
  type        = string

  validation {
    condition     = length(var.administrator_login) >= 1
    error_message = "administrator_login must not be empty."
  }
}

variable "administrator_login_password" {
  description = "Administrator login password for the SQL server"
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.administrator_login_password) >= 8
    error_message = "administrator_login_password must be at least 8 characters."
  }
}

variable "sku_name" {
  description = "SKU name for the MSSQL database (e.g. S0, GP_S_Gen5_1)"
  type        = string
  default     = "S0"

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
