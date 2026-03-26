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

variable "size" {
  description = "Azure VM size (e.g. Standard_B2s)"
  type        = string
  default     = "Standard_B2s"

  validation {
    condition     = can(regex("^Standard_", var.size))
    error_message = "size must be a valid Azure VM size starting with 'Standard_'."
  }
}

variable "subnet_id" {
  description = "Azure subnet resource ID for the VM network interface"
  type        = string

  validation {
    condition     = length(var.subnet_id) > 0
    error_message = "subnet_id must not be empty."
  }
}

variable "admin_username" {
  description = "Admin username for SSH access"
  type        = string

  validation {
    condition     = length(var.admin_username) >= 1 && length(var.admin_username) <= 64
    error_message = "admin_username must be between 1 and 64 characters."
  }
}

variable "admin_ssh_public_key" {
  description = "SSH public key for admin authentication (IA-2)"
  type        = string

  validation {
    condition     = length(var.admin_ssh_public_key) > 0
    error_message = "admin_ssh_public_key must not be empty."
  }
}

variable "source_image_reference" {
  description = "Source image reference for the VM"
  type = object({
    publisher = string
    offer     = string
    sku       = string
    version   = string
  })

  validation {
    condition     = length(var.source_image_reference.publisher) > 0
    error_message = "source_image_reference.publisher must not be empty."
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
