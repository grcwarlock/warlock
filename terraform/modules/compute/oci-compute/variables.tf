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
  description = "OCI compartment OCID where the instance will be created"
  type        = string

  validation {
    condition     = can(regex("^ocid1\\.compartment\\.", var.compartment_id))
    error_message = "compartment_id must be a valid OCI compartment OCID."
  }
}

variable "availability_domain" {
  description = "Availability domain for the compute instance"
  type        = string

  validation {
    condition     = length(var.availability_domain) > 0
    error_message = "availability_domain must not be empty."
  }
}

variable "shape" {
  description = "Compute instance shape (e.g. VM.Standard.E4.Flex)"
  type        = string
  default     = "VM.Standard.E4.Flex"

  validation {
    condition     = length(var.shape) > 0
    error_message = "shape must not be empty."
  }
}

variable "ocpus" {
  description = "Number of OCPUs for flexible shapes"
  type        = number
  default     = 1

  validation {
    condition     = var.ocpus >= 1
    error_message = "ocpus must be at least 1."
  }
}

variable "memory_in_gbs" {
  description = "Memory in GBs for flexible shapes"
  type        = number
  default     = 16

  validation {
    condition     = var.memory_in_gbs >= 1
    error_message = "memory_in_gbs must be at least 1."
  }
}

variable "subnet_id" {
  description = "OCID of the subnet for the instance VNIC"
  type        = string

  validation {
    condition     = can(regex("^ocid1\\.subnet\\.", var.subnet_id))
    error_message = "subnet_id must be a valid OCI subnet OCID."
  }
}

variable "image_id" {
  description = "OCID of the OS image for the boot volume"
  type        = string

  validation {
    condition     = can(regex("^ocid1\\.image\\.", var.image_id))
    error_message = "image_id must be a valid OCI image OCID."
  }
}

variable "ssh_public_key" {
  description = "SSH public key for instance metadata"
  type        = string

  validation {
    condition     = length(var.ssh_public_key) > 0
    error_message = "ssh_public_key must not be empty."
  }
}

variable "boot_volume_size_gbs" {
  description = "Boot volume size in GBs"
  type        = number
  default     = 50

  validation {
    condition     = var.boot_volume_size_gbs >= 50
    error_message = "boot_volume_size_gbs must be at least 50 GB."
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
