variable "name_prefix" {
  description = "Prefix applied to VPC, VSwitches, security groups, and related resources"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "vpc_cidr must be a valid CIDR block."
  }
}

variable "vswitch_cidrs" {
  description = "List of CIDR blocks for VSwitches (one per availability zone)"
  type        = list(string)

  validation {
    condition     = length(var.vswitch_cidrs) > 0
    error_message = "At least one VSwitch CIDR must be provided."
  }
}

variable "availability_zones" {
  description = "List of availability zones for VSwitch placement"
  type        = list(string)

  validation {
    condition     = length(var.availability_zones) > 0
    error_message = "At least one availability zone must be provided."
  }
}

variable "enable_nat" {
  description = "Whether to create a NAT Gateway for private subnet internet access"
  type        = bool
  default     = false
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
