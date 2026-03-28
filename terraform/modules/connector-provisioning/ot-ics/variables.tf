variable "name_prefix" {
  description = "Prefix applied to all resource names in this module"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "vendor" {
  description = "OT/ICS security vendor for connector access (claroty, dragos, or nozomi)"
  type        = string

  validation {
    condition     = contains(["claroty", "dragos", "nozomi"], var.vendor)
    error_message = "vendor must be one of: claroty, dragos, nozomi."
  }
}

variable "ot_network_cidr" {
  description = "CIDR block of the OT/ICS network where vendor appliances reside"
  type        = string

  validation {
    condition     = can(cidrhost(var.ot_network_cidr, 0))
    error_message = "ot_network_cidr must be a valid CIDR block."
  }
}

variable "warlock_network_cidr" {
  description = "CIDR block of the Warlock platform network"
  type        = string

  validation {
    condition     = can(cidrhost(var.warlock_network_cidr, 0))
    error_message = "warlock_network_cidr must be a valid CIDR block."
  }
}

variable "vpc_id" {
  description = "VPC ID where security groups and NACLs are created"
  type        = string

  validation {
    condition     = startswith(var.vpc_id, "vpc-")
    error_message = "vpc_id must start with 'vpc-'."
  }
}

variable "api_port" {
  description = "Port number for vendor API access. Null uses vendor default (443)."
  type        = number
  default     = null
}

variable "ot_subnet_ids" {
  description = "List of subnet IDs in the OT network (for NACL association)"
  type        = list(string)
  default     = []
}

variable "create_nacl" {
  description = "Whether to create a Network ACL for OT boundary enforcement. Set to false if managing NACLs externally."
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "Number of days to retain VPC flow logs in CloudWatch"
  type        = number
  default     = 90

  validation {
    condition     = var.log_retention_days > 0
    error_message = "log_retention_days must be greater than 0."
  }
}

variable "tags" {
  description = "Map of tags applied to all resources in this module"
  type        = map(string)
  default     = {}
}

variable "warlock_api_endpoint" {
  description = "Warlock API base URL for self-registration. Null disables registration."
  type        = string
  default     = null
}

variable "warlock_api_token" {
  description = "Bearer token for Warlock API self-registration"
  type        = string
  default     = null
  sensitive   = true
}
