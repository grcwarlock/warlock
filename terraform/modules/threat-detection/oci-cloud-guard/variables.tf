variable "name_prefix" {
  description = "Prefix applied to all resource display names"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "compartment_id" {
  description = "OCI compartment OCID to monitor with Cloud Guard"
  type        = string

  validation {
    condition     = can(regex("^ocid1\\.compartment\\.", var.compartment_id))
    error_message = "compartment_id must be a valid OCI compartment OCID."
  }
}

variable "tenancy_id" {
  description = "OCI tenancy OCID (Cloud Guard is enabled at tenancy level)"
  type        = string

  validation {
    condition     = can(regex("^ocid1\\.tenancy\\.", var.tenancy_id))
    error_message = "tenancy_id must be a valid OCI tenancy OCID."
  }
}

variable "reporting_region" {
  description = "Cloud Guard reporting region (e.g. us-ashburn-1)"
  type        = string
  default     = "us-ashburn-1"

  validation {
    condition     = length(var.reporting_region) > 0
    error_message = "reporting_region must not be empty."
  }
}

variable "source_detector_recipe_id" {
  description = "OCID of the Oracle-managed detector recipe to clone"
  type        = string

  validation {
    condition     = can(regex("^ocid1\\.cloudguarddetectorrecipe\\.", var.source_detector_recipe_id))
    error_message = "source_detector_recipe_id must be a valid Cloud Guard detector recipe OCID."
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
