variable "name_prefix" {
  description = "Prefix applied to all resource names"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "region" {
  description = "Linode region for the instance"
  type        = string
  default     = "us-east"
}

variable "type" {
  description = "Linode instance type (plan)"
  type        = string
  default     = "g6-standard-2"
}

variable "image" {
  description = "Linode image to deploy"
  type        = string
  default     = "linode/ubuntu22.04"
}

variable "authorized_keys" {
  description = "List of SSH public keys for root access"
  type        = list(string)

  validation {
    condition     = length(var.authorized_keys) > 0
    error_message = "At least one SSH public key must be provided."
  }
}

variable "tags" {
  description = "List of tag names applied to the instance"
  type        = list(string)
  default     = []
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
