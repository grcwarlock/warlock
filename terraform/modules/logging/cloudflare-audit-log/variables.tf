variable "name_prefix" {
  description = "Prefix applied to the logpush job name"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "zone_id" {
  description = "Cloudflare Zone ID for the logpush job"
  type        = string

  validation {
    condition     = length(var.zone_id) == 32
    error_message = "zone_id must be a 32-character Cloudflare zone identifier."
  }
}

variable "dataset" {
  description = "Logpush dataset (http_requests, firewall_events, etc.)"
  type        = string
  default     = "http_requests"

  validation {
    condition     = contains(["http_requests", "firewall_events", "spectrum_events", "dns_logs"], var.dataset)
    error_message = "dataset must be one of: http_requests, firewall_events, spectrum_events, dns_logs."
  }
}

variable "destination_conf" {
  description = "Logpush destination configuration (S3 URI, R2 URI, or HTTP endpoint)"
  type        = string

  validation {
    condition     = length(var.destination_conf) > 0
    error_message = "destination_conf must not be empty."
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
