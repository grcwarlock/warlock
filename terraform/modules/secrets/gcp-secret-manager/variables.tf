variable "project_id" {
  description = "GCP project ID where the secret will be created"
  type        = string

  validation {
    condition     = length(var.project_id) > 0
    error_message = "project_id must not be empty."
  }
}

variable "secret_id" {
  description = "ID of the secret in Secret Manager"
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9_-]{1,255}$", var.secret_id))
    error_message = "secret_id must be 1-255 alphanumeric characters, hyphens, or underscores."
  }
}

variable "secret_data" {
  description = "The secret data to store in the secret version"
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.secret_data) > 0
    error_message = "secret_data must not be empty."
  }
}

variable "replication_locations" {
  description = "List of GCP regions for user-managed replication. Empty list uses automatic replication."
  type        = list(string)
  default     = []
}

variable "kms_key_name" {
  description = "Cloud KMS key resource name for CMEK encryption. Null uses Google-managed keys."
  type        = string
  default     = null
}

variable "accessor_members" {
  description = "List of IAM members granted roles/secretmanager.secretAccessor (e.g. ['serviceAccount:sa@project.iam.gserviceaccount.com'])"
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
