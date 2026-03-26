variable "name_prefix" {
  description = "Prefix applied to all resource names"
  type        = string
  default     = "grc"

  # T-10: Enforce a non-empty, reasonably sized prefix
  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"

  # T-10: Validate CIDR is parseable
  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "vpc_cidr must be a valid CIDR block (e.g. 10.0.0.0/16)."
  }
}

variable "availability_zones" {
  description = "AZs for subnet placement -- must be explicitly provided (no default to avoid region assumptions)"
  type        = list(string)

  validation {
    condition     = length(var.availability_zones) >= 1
    error_message = "At least one availability zone must be provided."
  }
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.10.0/24", "10.0.11.0/24"]
}

variable "enable_flow_logs" {
  description = "Enable VPC flow logs (AU-2)"
  type        = bool
  default     = true
}

variable "flow_log_retention_days" {
  description = "CloudWatch log retention in days for VPC flow logs"
  type        = number
  default     = 365

  # T-10: Retention must be a positive integer
  validation {
    condition     = var.flow_log_retention_days > 0
    error_message = "flow_log_retention_days must be greater than 0."
  }
}

# T-6: Optional KMS key for encrypting the flow logs CloudWatch log group
variable "flow_logs_kms_key_id" {
  description = "ARN of a KMS key to encrypt the flow logs CloudWatch log group. If null, CloudWatch-managed encryption is used."
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
