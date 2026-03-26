variable "name_prefix" {
  description = "Prefix applied to ECS instance and security group names"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "image_id" {
  description = "Huawei Cloud image ID for the ECS instance"
  type        = string

  validation {
    condition     = length(var.image_id) > 0
    error_message = "image_id must not be empty."
  }
}

variable "flavor_id" {
  description = "ECS flavor (instance type), e.g. s6.large.2"
  type        = string
  default     = "s6.large.2"

  validation {
    condition     = length(var.flavor_id) > 0
    error_message = "flavor_id must not be empty."
  }
}

variable "availability_zone" {
  description = "Availability zone for the ECS instance"
  type        = string

  validation {
    condition     = length(var.availability_zone) > 0
    error_message = "availability_zone must not be empty."
  }
}

variable "subnet_id" {
  description = "Subnet ID for the ECS instance network interface"
  type        = string

  validation {
    condition     = length(var.subnet_id) > 0
    error_message = "subnet_id must not be empty."
  }
}

variable "security_group_id" {
  description = "Optional external security group ID. When null, a module-managed group is used."
  type        = string
  default     = null
}

variable "kms_key_id" {
  description = "Optional KMS key ID for data disk encryption (SC-28)"
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
