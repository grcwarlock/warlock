variable "name_prefix" {
  description = "Organization or team name prefix for the Heroku app"
  type        = string

  validation {
    condition     = length(var.name_prefix) > 0
    error_message = "name_prefix must not be empty."
  }
}

variable "region" {
  description = "Heroku region (us or eu)"
  type        = string
  default     = "us"

  validation {
    condition     = contains(["us", "eu"], var.region)
    error_message = "region must be 'us' or 'eu'."
  }
}

variable "app_name" {
  description = "Name of the Heroku application"
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,29}$", var.app_name))
    error_message = "app_name must be 3-30 lowercase alphanumeric characters or hyphens, starting with a letter."
  }
}

variable "env_vars" {
  description = "Sensitive environment variables to set on the Heroku app (WLK_* config)"
  type        = map(string)
  default     = {}
  sensitive   = true
}

variable "formation_quantity" {
  description = "Number of dynos for the web formation"
  type        = number
  default     = 1

  validation {
    condition     = var.formation_quantity >= 1
    error_message = "formation_quantity must be at least 1."
  }
}

variable "formation_size" {
  description = "Dyno size for the web formation (e.g. basic, standard-1x, standard-2x)"
  type        = string
  default     = "basic"

  validation {
    condition     = contains(["basic", "standard-1x", "standard-2x", "performance-m", "performance-l"], var.formation_size)
    error_message = "formation_size must be one of: basic, standard-1x, standard-2x, performance-m, performance-l."
  }
}

variable "tags" {
  description = "Common tags for all resources"
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
