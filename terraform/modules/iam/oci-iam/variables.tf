variable "name_prefix" {
  description = "Prefix applied to all resource display names"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "tenancy_id" {
  description = "OCI tenancy OCID (root compartment for IAM resources)"
  type        = string

  validation {
    condition     = can(regex("^ocid1\\.tenancy\\.", var.tenancy_id))
    error_message = "tenancy_id must be a valid OCI tenancy OCID."
  }
}

variable "compartment_id" {
  description = "Parent compartment OCID where the workload compartment will be created"
  type        = string

  validation {
    condition     = can(regex("^ocid1\\.(tenancy|compartment)\\.", var.compartment_id))
    error_message = "compartment_id must be a valid OCI tenancy or compartment OCID."
  }
}

variable "auditor_group_name" {
  description = "Name for the auditor IAM group"
  type        = string
  default     = "warlock-auditors"

  validation {
    condition     = length(var.auditor_group_name) > 0
    error_message = "auditor_group_name must not be empty."
  }
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
