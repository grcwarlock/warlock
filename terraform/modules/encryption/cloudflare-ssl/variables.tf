variable "zone_id" {
  description = "Cloudflare Zone ID to configure SSL/TLS settings"
  type        = string

  validation {
    condition     = length(var.zone_id) == 32
    error_message = "zone_id must be a 32-character Cloudflare zone identifier."
  }
}

variable "min_tls_version" {
  description = "Minimum TLS version (1.0, 1.1, 1.2, 1.3)"
  type        = string
  default     = "1.2"

  validation {
    condition     = contains(["1.0", "1.1", "1.2", "1.3"], var.min_tls_version)
    error_message = "min_tls_version must be one of: 1.0, 1.1, 1.2, 1.3."
  }
}

variable "enable_origin_pulls" {
  description = "Enable Cloudflare Authenticated Origin Pulls (mTLS)"
  type        = bool
  default     = false
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
