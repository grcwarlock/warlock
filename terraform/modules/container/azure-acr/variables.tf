variable "name_prefix" {
  description = "Prefix applied to all resource names. ACR names must be alphanumeric only."
  type        = string
  default     = "warlock"

  validation {
    condition     = can(regex("^[a-z0-9]{2,20}$", var.name_prefix))
    error_message = "name_prefix must be 2-20 lowercase alphanumeric characters (ACR naming constraint)."
  }
}

variable "location" {
  description = "Azure region for the Container Registry"
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

variable "sku" {
  description = "ACR SKU tier — Premium recommended for geo-replication and content trust"
  type        = string
  default     = "Premium"

  validation {
    condition     = contains(["Basic", "Standard", "Premium"], var.sku)
    error_message = "sku must be one of: Basic, Standard, Premium."
  }
}

variable "georeplication_locations" {
  description = "List of Azure regions for geo-replication (Premium SKU only)"
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
