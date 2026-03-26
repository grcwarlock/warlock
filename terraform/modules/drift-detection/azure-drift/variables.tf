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
  description = "Azure region for all drift detection resources"
  type        = string

  validation {
    condition     = length(var.location) > 0
    error_message = "location must not be empty."
  }
}

variable "schedule_frequency" {
  description = "Frequency of the drift detection schedule (Hour, Day, Week, Month)"
  type        = string
  default     = "Hour"

  validation {
    condition     = contains(["Hour", "Day", "Week", "Month"], var.schedule_frequency)
    error_message = "schedule_frequency must be one of: Hour, Day, Week, Month."
  }
}

variable "schedule_interval" {
  description = "Interval between drift detection runs (combined with schedule_frequency)"
  type        = number
  default     = 1

  validation {
    condition     = var.schedule_interval >= 1 && var.schedule_interval <= 100
    error_message = "schedule_interval must be between 1 and 100."
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
