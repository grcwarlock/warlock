variable "name_prefix" {
  description = "Prefix applied to all resource names"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "region" {
  description = "IBM Cloud region"
  type        = string
  default     = "us-south"

  validation {
    condition     = length(var.region) > 0
    error_message = "region must not be empty."
  }
}

variable "zone" {
  description = "Availability zone for the VSI (e.g. us-south-1)"
  type        = string
  default     = "us-south-1"

  validation {
    condition     = length(var.zone) > 0
    error_message = "zone must not be empty."
  }
}

variable "resource_group_id" {
  description = "IBM Cloud resource group ID"
  type        = string

  validation {
    condition     = length(var.resource_group_id) > 0
    error_message = "resource_group_id must not be empty."
  }
}

variable "vpc_id" {
  description = "ID of the VPC for the instance"
  type        = string

  validation {
    condition     = length(var.vpc_id) > 0
    error_message = "vpc_id must not be empty."
  }
}

variable "subnet_id" {
  description = "ID of the subnet for the primary network interface"
  type        = string

  validation {
    condition     = length(var.subnet_id) > 0
    error_message = "subnet_id must not be empty."
  }
}

variable "image_id" {
  description = "ID of the OS image for the instance"
  type        = string

  validation {
    condition     = length(var.image_id) > 0
    error_message = "image_id must not be empty."
  }
}

variable "profile" {
  description = "VSI profile (e.g. bx2-2x8)"
  type        = string
  default     = "bx2-2x8"

  validation {
    condition     = length(var.profile) > 0
    error_message = "profile must not be empty."
  }
}

variable "ssh_key_ids" {
  description = "List of SSH key IDs to inject into the instance"
  type        = list(string)

  validation {
    condition     = length(var.ssh_key_ids) > 0
    error_message = "At least one SSH key ID must be provided."
  }
}

variable "boot_volume_encryption_key" {
  description = "CRN of the Key Protect key for boot volume encryption. Null uses provider-managed encryption."
  type        = string
  default     = null
}

variable "tags" {
  description = "List of tags applied to all resources in this module"
  type        = list(string)
  default     = []
}

# -- Warlock integration -------------------------------------------------------

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
