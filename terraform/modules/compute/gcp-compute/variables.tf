variable "project_id" {
  description = "GCP project ID where the instance will be created"
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

variable "zone" {
  description = "GCP zone for the instance (e.g. us-central1-a)"
  type        = string

  validation {
    condition     = length(var.zone) > 0
    error_message = "zone must not be empty."
  }
}

variable "machine_type" {
  description = "GCE machine type (e.g. e2-micro)"
  type        = string
  default     = "e2-micro"

  validation {
    condition     = length(var.machine_type) > 0
    error_message = "machine_type must not be empty."
  }
}

variable "subnet_self_link" {
  description = "Self-link of the VPC subnet for the instance network interface"
  type        = string

  validation {
    condition     = length(var.subnet_self_link) > 0
    error_message = "subnet_self_link must not be empty."
  }
}

variable "source_image" {
  description = "Source image for the boot disk (e.g. debian-cloud/debian-12)"
  type        = string

  validation {
    condition     = length(var.source_image) > 0
    error_message = "source_image must not be empty."
  }
}

variable "kms_key_self_link" {
  description = "Self-link of a Cloud KMS key for CMEK boot disk encryption (SC-28). Null uses Google-managed key."
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
