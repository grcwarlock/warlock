variable "name_prefix" {
  description = "Prefix applied to KMS key alias and related resources"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "rotation_period" {
  description = "Automatic rotation interval for the KMS key (e.g. 365d). SC-12 requires regular rotation."
  type        = string
  default     = "365d"

  validation {
    condition     = can(regex("^[0-9]+d$", var.rotation_period))
    error_message = "rotation_period must be a duration string ending in 'd' (e.g. '365d')."
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
