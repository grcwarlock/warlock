###############################################################################
# Variables — Warlock Azure Container Apps Deployment
###############################################################################

# -- Naming and tagging -------------------------------------------------------

variable "name_prefix" {
  description = "Prefix applied to all resource names"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "environment" {
  description = "Deployment environment (e.g. dev, staging, production)"
  type        = string
  default     = "production"

  validation {
    condition     = contains(["dev", "staging", "production"], var.environment)
    error_message = "environment must be dev, staging, or production."
  }
}

variable "team" {
  description = "Team owning this deployment"
  type        = string
  default     = "platform"
}

variable "tags" {
  description = "Additional tags applied to all resources"
  type        = map(string)
  default     = {}
}

# -- Location -----------------------------------------------------------------

variable "location" {
  description = "Azure region for all resources"
  type        = string
}

# -- Container ----------------------------------------------------------------

variable "container_image" {
  description = "Container image URI for the Warlock application"
  type        = string
}

variable "api_cpu" {
  description = "CPU cores allocated to each container app (e.g. 0.5, 1.0, 2.0)"
  type        = number
  default     = 1.0

  validation {
    condition     = var.api_cpu >= 0.25 && var.api_cpu <= 4.0
    error_message = "api_cpu must be between 0.25 and 4.0."
  }
}

variable "api_memory" {
  description = "Memory allocated to each container app (e.g. 1Gi, 2Gi)"
  type        = string
  default     = "2Gi"

  validation {
    condition     = can(regex("^[0-9]+(\\.[0-9]+)?Gi$", var.api_memory))
    error_message = "api_memory must be in the format NGi (e.g. 2Gi)."
  }
}

variable "min_replicas" {
  description = "Minimum number of API container replicas"
  type        = number
  default     = 1

  validation {
    condition     = var.min_replicas >= 0 && var.min_replicas <= 25
    error_message = "min_replicas must be between 0 and 25."
  }
}

variable "max_replicas" {
  description = "Maximum number of API container replicas"
  type        = number
  default     = 5

  validation {
    condition     = var.max_replicas >= 1 && var.max_replicas <= 25
    error_message = "max_replicas must be between 1 and 25."
  }
}

# -- Database -----------------------------------------------------------------

variable "db_sku_name" {
  description = "PostgreSQL Flexible Server SKU"
  type        = string
  default     = "B_Standard_B1ms"
}

# -- Redis --------------------------------------------------------------------

variable "redis_sku" {
  description = "Azure Redis Cache SKU (Basic, Standard, Premium)"
  type        = string
  default     = "Basic"

  validation {
    condition     = contains(["Basic", "Standard", "Premium"], var.redis_sku)
    error_message = "redis_sku must be Basic, Standard, or Premium."
  }
}

# -- Logging ------------------------------------------------------------------

variable "log_retention_days" {
  description = "Log Analytics workspace retention in days"
  type        = number
  default     = 90

  validation {
    condition     = var.log_retention_days >= 30 && var.log_retention_days <= 730
    error_message = "log_retention_days must be between 30 and 730."
  }
}

# -- Warlock application config -----------------------------------------------

variable "wlk_jwt_secret" {
  description = "Warlock JWT signing secret (32+ characters)"
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.wlk_jwt_secret) >= 32
    error_message = "wlk_jwt_secret must be at least 32 characters."
  }
}

variable "wlk_ai_enabled" {
  description = "Enable AI-powered compliance assessments"
  type        = string
  default     = "false"

  validation {
    condition     = contains(["true", "false"], var.wlk_ai_enabled)
    error_message = "wlk_ai_enabled must be 'true' or 'false'."
  }
}

variable "wlk_opa_url" {
  description = "OPA server URL for policy evaluation"
  type        = string
  default     = "http://localhost:8181"
}

# -- Warlock closed-loop registration -----------------------------------------

variable "warlock_api_endpoint" {
  description = "Warlock API base URL for self-registration. Null disables registration."
  type        = string
  default     = null
}

variable "warlock_api_token" {
  description = "Bearer token for Warlock API self-registration"
  type        = string
  default     = null
  sensitive   = true
}

variable "warlock_remediation_id" {
  description = "Remediation ID when triggered by closed-loop engine. Null = standalone."
  type        = string
  default     = null
}
