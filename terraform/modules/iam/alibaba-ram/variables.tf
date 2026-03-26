variable "name_prefix" {
  description = "Prefix applied to RAM roles, policies, and related resources"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "trusted_account_ids" {
  description = "List of Alibaba Cloud account IDs trusted to assume the auditor role"
  type        = list(string)

  validation {
    condition     = length(var.trusted_account_ids) > 0
    error_message = "At least one trusted account ID must be provided."
  }
}

variable "tags" {
  description = "Map of tags applied to all taggable resources in this module"
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
