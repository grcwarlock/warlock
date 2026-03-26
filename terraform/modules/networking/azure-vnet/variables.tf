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
  description = "Azure region for all networking resources (e.g. eastus)"
  type        = string

  validation {
    condition     = length(var.location) > 0
    error_message = "location must not be empty."
  }
}

variable "resource_group_name" {
  description = "Name of the Azure resource group for all networking resources"
  type        = string

  validation {
    condition     = length(var.resource_group_name) > 0
    error_message = "resource_group_name must not be empty."
  }
}

variable "address_space" {
  description = "List of CIDR blocks for the virtual network address space"
  type        = list(string)
  default     = ["10.0.0.0/16"]

  validation {
    condition     = length(var.address_space) > 0
    error_message = "address_space must contain at least one CIDR block."
  }
}

variable "public_subnet_prefixes" {
  description = "List of CIDR prefixes for public subnets"
  type        = list(string)
  default     = ["10.0.1.0/24"]

  validation {
    condition     = length(var.public_subnet_prefixes) > 0
    error_message = "public_subnet_prefixes must contain at least one CIDR prefix."
  }
}

variable "private_subnet_prefixes" {
  description = "List of CIDR prefixes for private subnets"
  type        = list(string)
  default     = ["10.0.2.0/24"]

  validation {
    condition     = length(var.private_subnet_prefixes) > 0
    error_message = "private_subnet_prefixes must contain at least one CIDR prefix."
  }
}

variable "enable_flow_logs" {
  description = "Enable NSG flow logs for network traffic analysis (AU-2)"
  type        = bool
  default     = true
}

variable "flow_log_storage_account_id" {
  description = "Resource ID of a storage account for NSG flow logs. Required when enable_flow_logs is true."
  type        = string
  default     = null
}

variable "log_analytics_workspace_id" {
  description = "Resource ID of a Log Analytics workspace for traffic analytics. Set to null to skip."
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
