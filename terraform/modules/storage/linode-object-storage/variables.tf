variable "name_prefix" {
  description = "Prefix applied to resource names"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "label" {
  description = "Label for the object storage bucket"
  type        = string

  validation {
    condition     = length(var.label) >= 3 && length(var.label) <= 63
    error_message = "label must be between 3 and 63 characters."
  }
}

variable "cluster" {
  description = "Linode Object Storage cluster (e.g. us-east-1)"
  type        = string
  default     = "us-east-1"
}

variable "acl" {
  description = "Access control list for the bucket"
  type        = string
  default     = "private"

  validation {
    condition     = contains(["private", "public-read", "authenticated-read", "public-read-write"], var.acl)
    error_message = "acl must be one of: private, public-read, authenticated-read, public-read-write."
  }
}

variable "create_access_key" {
  description = "Create an Object Storage access key for this bucket"
  type        = bool
  default     = false
}

variable "tags" {
  description = "List of tag names (Linode uses string tags, not maps)"
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
