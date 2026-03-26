variable "name_prefix" {
  description = "Prefix applied to all resource names"
  type        = string
  default     = "grc"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "namespace" {
  description = "Kubernetes namespace for the deployment"
  type        = string

  validation {
    condition     = length(var.namespace) >= 1 && length(var.namespace) <= 63
    error_message = "namespace must be between 1 and 63 characters."
  }
}

variable "image" {
  description = "Container image (e.g. registry/repo:tag)"
  type        = string

  validation {
    condition     = length(var.image) >= 1
    error_message = "image must not be empty."
  }
}

variable "replicas" {
  description = "Number of pod replicas"
  type        = number
  default     = 2

  validation {
    condition     = var.replicas >= 1
    error_message = "replicas must be at least 1."
  }
}

variable "container_port" {
  description = "Container port to expose"
  type        = number
  default     = 8080

  validation {
    condition     = var.container_port > 0 && var.container_port <= 65535
    error_message = "container_port must be between 1 and 65535."
  }
}

variable "cpu_limit" {
  description = "CPU resource limit (e.g. 500m, 1)"
  type        = string
  default     = "500m"
}

variable "memory_limit" {
  description = "Memory resource limit (e.g. 512Mi, 1Gi)"
  type        = string
  default     = "512Mi"
}

variable "labels" {
  description = "Labels applied to all resources in this module"
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
