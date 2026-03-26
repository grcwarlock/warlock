variable "project_id" {
  description = "GCP project ID for the Artifact Registry repository"
  type        = string

  validation {
    condition     = length(var.project_id) > 0
    error_message = "project_id must not be empty."
  }
}

variable "name_prefix" {
  description = "Prefix applied to the repository name"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "location" {
  description = "GCP region for the Artifact Registry repository"
  type        = string

  validation {
    condition     = length(var.location) > 0
    error_message = "location must not be empty."
  }
}

variable "kms_key_name" {
  description = "Fully-qualified Cloud KMS key name for CMEK encryption. Null uses Google-managed encryption."
  type        = string
  default     = null
}

variable "reader_members" {
  description = "List of IAM members granted artifactregistry.reader on the repository"
  type        = list(string)
  default     = []
}

variable "writer_members" {
  description = "List of IAM members granted artifactregistry.writer on the repository"
  type        = list(string)
  default     = []
}

variable "labels" {
  description = "Map of GCP labels applied to all resources in this module"
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
