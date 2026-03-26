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
  description = "DigitalOcean App Platform region"
  type        = string
  default     = "nyc"
}

variable "container_image" {
  description = "Container image reference for the Warlock application"
  type        = string

  validation {
    condition     = length(var.container_image) > 0
    error_message = "container_image must not be empty."
  }
}

variable "instance_count" {
  description = "Number of API service instances"
  type        = number
  default     = 1

  validation {
    condition     = var.instance_count >= 1 && var.instance_count <= 10
    error_message = "instance_count must be between 1 and 10."
  }
}

variable "instance_size" {
  description = "App Platform instance size slug"
  type        = string
  default     = "basic-xxs"
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
