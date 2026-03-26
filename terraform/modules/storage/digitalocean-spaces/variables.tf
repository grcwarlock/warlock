variable "name_prefix" {
  description = "Prefix applied to all resource names"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "region" {
  description = "DigitalOcean region for the Spaces bucket"
  type        = string
  default     = "nyc3"
}

variable "acl" {
  description = "Access control list for the bucket (private or public-read)"
  type        = string
  default     = "private"

  validation {
    condition     = contains(["private", "public-read"], var.acl)
    error_message = "acl must be either 'private' or 'public-read'."
  }
}

variable "cors_rules" {
  description = "Optional CORS rules for the Spaces bucket"
  type = list(object({
    allowed_headers = list(string)
    allowed_methods = list(string)
    allowed_origins = list(string)
    max_age_seconds = number
  }))
  default = []
}

variable "tags" {
  description = "List of tag names (DigitalOcean uses string tags, not maps)"
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
