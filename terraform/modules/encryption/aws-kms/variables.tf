variable "name_prefix" {
  description = "Prefix applied to all resource names and the KMS alias"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "description" {
  description = "Human-readable description for the KMS key"
  type        = string
  default     = "Warlock GRC platform baseline KMS key"

  validation {
    condition     = length(var.description) >= 5
    error_message = "description must be at least 5 characters."
  }
}

variable "deletion_window_in_days" {
  description = "Number of days before a scheduled key deletion takes effect (7-30)"
  type        = number
  default     = 30

  validation {
    condition     = var.deletion_window_in_days >= 7 && var.deletion_window_in_days <= 30
    error_message = "deletion_window_in_days must be between 7 and 30."
  }
}

variable "multi_region" {
  description = "Create a multi-region primary key (SC-12 continuity)"
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
