variable "name_prefix" {
  description = "Prefix applied to all resource names"
  type        = string
  default     = "grc"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "service_name" {
  description = "OVH Cloud project ID"
  type        = string

  validation {
    condition     = length(var.service_name) > 0
    error_message = "service_name (OVH project ID) must not be empty."
  }
}

variable "vrack_id" {
  description = "OVH vRack service name / ID"
  type        = string

  validation {
    condition     = length(var.vrack_id) > 0
    error_message = "vrack_id must not be empty."
  }
}

variable "region" {
  description = "OVH region for the private network (e.g. GRA11, SBG5, BHS5)"
  type        = string
  default     = "GRA11"
}

variable "subnet_cidr" {
  description = "CIDR block for the private subnet"
  type        = string
  default     = "10.0.0.0/24"

  validation {
    condition     = can(cidrhost(var.subnet_cidr, 0))
    error_message = "subnet_cidr must be a valid CIDR block (e.g. 10.0.0.0/24)."
  }
}

variable "vlan_id" {
  description = "VLAN ID for the private network (0-4095)"
  type        = number
  default     = 0

  validation {
    condition     = var.vlan_id >= 0 && var.vlan_id <= 4095
    error_message = "vlan_id must be between 0 and 4095."
  }
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
