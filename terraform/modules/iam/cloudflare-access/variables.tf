variable "zone_id" {
  description = "Cloudflare Zone ID"
  type        = string

  validation {
    condition     = length(var.zone_id) == 32
    error_message = "zone_id must be a 32-character Cloudflare zone identifier."
  }
}

variable "account_id" {
  description = "Cloudflare Account ID"
  type        = string

  validation {
    condition     = length(var.account_id) == 32
    error_message = "account_id must be a 32-character Cloudflare account identifier."
  }
}

variable "app_name" {
  description = "Name of the Cloudflare Access application"
  type        = string

  validation {
    condition     = length(var.app_name) >= 2
    error_message = "app_name must be at least 2 characters."
  }
}

variable "domain" {
  description = "Domain to protect with Cloudflare Access"
  type        = string

  validation {
    condition     = length(var.domain) > 0
    error_message = "domain must not be empty."
  }
}

variable "allowed_email_domains" {
  description = "List of email domains allowed to access the application"
  type        = list(string)

  validation {
    condition     = length(var.allowed_email_domains) > 0
    error_message = "At least one allowed email domain must be specified."
  }
}

variable "session_duration" {
  description = "Session duration for authenticated users"
  type        = string
  default     = "24h"

  validation {
    condition     = can(regex("^[0-9]+[hm]$", var.session_duration))
    error_message = "session_duration must be a valid duration (e.g. 24h, 30m)."
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
