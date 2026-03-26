variable "name_prefix" {
  description = "Prefix applied to all resource names"
  type        = string
  default     = "grc"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "service_name" {
  description = "OVH Cloud project ID"
  type        = string

  validation {
    condition     = length(var.service_name) > 0
    error_message = "service_name (OVH project ID) must not be empty."
  }
}

variable "region" {
  description = "OVH region for object storage (e.g. GRA, SBG, BHS)"
  type        = string
  default     = "GRA"
}

variable "container_read_acl" {
  description = "OpenStack container read ACL. Empty string = project-only access."
  type        = string
  default     = ""
}

variable "container_write_acl" {
  description = "OpenStack container write ACL. Empty string = project-only access."
  type        = string
  default     = ""
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
