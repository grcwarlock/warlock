variable "name_prefix" {
  description = "Prefix applied to all resource names"
  type        = string
  default     = "grc"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "zone" {
  description = "Scaleway availability zone (e.g. fr-par-1, nl-ams-1)"
  type        = string
  default     = "fr-par-1"
}

variable "type" {
  description = "Scaleway instance type (e.g. DEV1-S, DEV1-M, GP1-S)"
  type        = string
  default     = "DEV1-S"
}

variable "image" {
  description = "Instance image (e.g. ubuntu_jammy, debian_bookworm)"
  type        = string
  default     = "ubuntu_jammy"
}

variable "enable_public_ip" {
  description = "Whether to assign a public IPv4 address. False = private-only."
  type        = bool
  default     = false
}

variable "security_group_id" {
  description = "ID of a Scaleway security group to attach. Null uses default."
  type        = string
  default     = null
}

variable "tags" {
  description = "List of tags applied to all resources"
  type        = list(string)
  default     = []
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
