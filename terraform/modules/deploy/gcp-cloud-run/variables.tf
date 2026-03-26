###############################################################################
# Variables — Warlock GCP Cloud Run Deployment
###############################################################################

# -- Project and region -------------------------------------------------------

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region for all resources"
  type        = string
}

# -- Naming and labeling ------------------------------------------------------

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

variable "labels" {
  description = "Additional labels applied to all resources"
  type        = map(string)
  default     = {}
}

# -- Container ----------------------------------------------------------------

variable "container_image" {
  description = "Container image URI for the Warlock application (e.g. gcr.io/project/warlock:latest)"
  type        = string
}

variable "cpu" {
  description = "CPU limit for each Cloud Run instance (e.g. 1, 2)"
  type        = string
  default     = "1"

  validation {
    condition     = contains(["1", "2", "4", "8"], var.cpu)
    error_message = "cpu must be 1, 2, 4, or 8."
  }
}

variable "memory" {
  description = "Memory limit for each Cloud Run instance (e.g. 512Mi, 1Gi, 2Gi)"
  type        = string
  default     = "2Gi"

  validation {
    condition     = can(regex("^[0-9]+(Mi|Gi)$", var.memory))
    error_message = "memory must be in the format NMi or NGi (e.g. 2Gi, 512Mi)."
  }
}

variable "min_instances" {
  description = "Minimum number of Cloud Run API instances"
  type        = number
  default     = 0

  validation {
    condition     = var.min_instances >= 0 && var.min_instances <= 100
    error_message = "min_instances must be between 0 and 100."
  }
}

variable "max_instances" {
  description = "Maximum number of Cloud Run API instances"
  type        = number
  default     = 10

  validation {
    condition     = var.max_instances >= 1 && var.max_instances <= 100
    error_message = "max_instances must be between 1 and 100."
  }
}

# -- Database -----------------------------------------------------------------

variable "db_tier" {
  description = "Cloud SQL machine tier"
  type        = string
  default     = "db-f1-micro"
}

variable "deletion_protection" {
  description = "Enable deletion protection on Cloud SQL (disable only for dev/test)"
  type        = bool
  default     = true
}

# -- Redis --------------------------------------------------------------------

variable "redis_memory_size_gb" {
  description = "Memorystore Redis instance size in GB"
  type        = number
  default     = 1

  validation {
    condition     = var.redis_memory_size_gb >= 1 && var.redis_memory_size_gb <= 300
    error_message = "redis_memory_size_gb must be between 1 and 300."
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
