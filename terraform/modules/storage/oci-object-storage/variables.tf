variable "name_prefix" {
  description = "Prefix applied to the bucket name"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "compartment_id" {
  description = "OCI compartment OCID where the bucket will be created"
  type        = string

  validation {
    condition     = can(regex("^ocid1\\.compartment\\.", var.compartment_id))
    error_message = "compartment_id must be a valid OCI compartment OCID."
  }
}

variable "namespace" {
  description = "Object Storage namespace for the bucket"
  type        = string

  validation {
    condition     = length(var.namespace) > 0
    error_message = "namespace must not be empty."
  }
}

variable "kms_key_id" {
  description = "OCID of the KMS key for customer-managed encryption. Null uses Oracle-managed keys."
  type        = string
  default     = null
}

variable "tags" {
  description = "Map of freeform tags applied to all resources in this module"
  type        = map(string)
  default     = {}
}

# -- Warlock integration -------------------------------------------------------

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
