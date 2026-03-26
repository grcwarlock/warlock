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
  description = "Alibaba Cloud image ID for the ECS instance"
  type        = string

  validation {
    condition     = length(var.image_id) > 0
    error_message = "image_id must not be empty."
  }
}

variable "instance_type" {
  description = "ECS instance type (e.g. ecs.t6-c1m1.large)"
  type        = string
  default     = "ecs.t6-c1m1.large"

  validation {
    condition     = length(var.instance_type) > 0
    error_message = "instance_type must not be empty."
  }
}

variable "vpc_id" {
  description = "VPC ID where the security group will be created"
  type        = string

  validation {
    condition     = length(var.vpc_id) > 0
    error_message = "vpc_id must not be empty."
  }
}

variable "vswitch_id" {
  description = "VSwitch ID for the ECS instance placement"
  type        = string

  validation {
    condition     = length(var.vswitch_id) > 0
    error_message = "vswitch_id must not be empty."
  }
}

variable "security_group_id" {
  description = "Optional external security group ID. When null, a module-managed group is used."
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
