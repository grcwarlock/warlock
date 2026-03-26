variable "name_prefix" {
  description = "Prefix applied to ruleset names"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "zone_id" {
  description = "Cloudflare Zone ID for WAF configuration"
  type        = string

  validation {
    condition     = length(var.zone_id) == 32
    error_message = "zone_id must be a 32-character Cloudflare zone identifier."
  }
}

variable "enable_owasp" {
  description = "Deploy Cloudflare OWASP Core Ruleset in addition to Managed Ruleset"
  type        = bool
  default     = true
}

variable "security_level" {
  description = "Cloudflare security level (off, essentially_off, low, medium, high, under_attack)"
  type        = string
  default     = "medium"

  validation {
    condition     = contains(["off", "essentially_off", "low", "medium", "high", "under_attack"], var.security_level)
    error_message = "security_level must be one of: off, essentially_off, low, medium, high, under_attack."
  }
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
