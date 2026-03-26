variable "project_id" {
  description = "GCP project ID where IAM resources will be configured"
  type        = string

  validation {
    condition     = length(var.project_id) > 0
    error_message = "project_id must not be empty."
  }
}

variable "name_prefix" {
  description = "Prefix applied to the custom role and other resources"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "auditor_members" {
  description = "List of IAM members to grant the custom auditor role (e.g. ['user:alice@example.com', 'serviceAccount:sa@project.iam.gserviceaccount.com'])"
  type        = list(string)

  validation {
    condition     = length(var.auditor_members) > 0
    error_message = "auditor_members must contain at least one member."
  }
}

variable "enable_domain_restriction" {
  description = "Enable organization policy to restrict IAM sharing to allowed domains only (AC-6)"
  type        = bool
  default     = false
}

variable "allowed_domains" {
  description = "List of allowed domain IDs when domain restriction is enabled (e.g. ['C0xxxxxxx'] for Google Workspace customer IDs)"
  type        = list(string)
  default     = []
}

variable "labels" {
  description = "Map of GCP labels (not applied to IAM resources but kept for module interface consistency)"
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
