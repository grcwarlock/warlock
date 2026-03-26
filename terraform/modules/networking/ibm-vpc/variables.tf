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
  description = "IBM Cloud region for VPC resources"
  type        = string
  default     = "us-south"

  validation {
    condition     = length(var.region) > 0
    error_message = "region must not be empty."
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

variable "vpc_cidr" {
  description = "Overall VPC CIDR block (informational, actual allocation via subnet_cidrs)"
  type        = string
  default     = "10.0.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "vpc_cidr must be a valid CIDR block."
  }
}

variable "zones" {
  description = "List of availability zones (e.g. ['us-south-1', 'us-south-2'])"
  type        = list(string)
  default     = ["us-south-1", "us-south-2", "us-south-3"]

  validation {
    condition     = length(var.zones) > 0
    error_message = "At least one zone must be specified."
  }
}

variable "subnet_cidrs" {
  description = "List of CIDR blocks for subnets, one per zone (must match length of zones)"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]

  validation {
    condition     = length(var.subnet_cidrs) > 0
    error_message = "At least one subnet CIDR must be specified."
  }
}

variable "enable_public_gateway" {
  description = "Whether to create public gateways for each zone"
  type        = bool
  default     = false
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
