variable "project_id" {
  description = "GCP project ID where the Cloud Function will be created"
  type        = string

  validation {
    condition     = length(var.project_id) > 0
    error_message = "project_id must not be empty."
  }
}

variable "name_prefix" {
  description = "Prefix applied to all resource names"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "location" {
  description = "GCP region for the Cloud Function (e.g. us-central1)"
  type        = string

  validation {
    condition     = length(var.location) > 0
    error_message = "location must not be empty."
  }
}

variable "runtime" {
  description = "Runtime for the Cloud Function (e.g. python312, nodejs20)"
  type        = string
  default     = "python312"

  validation {
    condition     = length(var.runtime) > 0
    error_message = "runtime must not be empty."
  }
}

variable "entry_point" {
  description = "Name of the function entrypoint in the source code"
  type        = string

  validation {
    condition     = length(var.entry_point) > 0
    error_message = "entry_point must not be empty."
  }
}

variable "source_bucket" {
  description = "GCS bucket containing the function source archive"
  type        = string

  validation {
    condition     = length(var.source_bucket) > 0
    error_message = "source_bucket must not be empty."
  }
}

variable "source_object" {
  description = "GCS object path of the function source archive (.zip)"
  type        = string

  validation {
    condition     = length(var.source_object) > 0
    error_message = "source_object must not be empty."
  }
}

variable "vpc_connector" {
  description = "Fully-qualified name of the VPC connector for egress (SC-7). Null disables VPC routing."
  type        = string
  default     = null
}

variable "service_account_email" {
  description = "Service account email for the Cloud Function. Null uses the default compute SA."
  type        = string
  default     = null
}

variable "invoker_member" {
  description = "IAM member to grant Cloud Run invoker role (e.g. allUsers, serviceAccount:sa@project.iam). Null skips."
  type        = string
  default     = null
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
