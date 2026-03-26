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
  description = "Kubernetes namespace to apply network policies to"
  type        = string

  validation {
    condition     = length(var.namespace) >= 1 && length(var.namespace) <= 63
    error_message = "namespace must be between 1 and 63 characters."
  }
}

variable "allowed_namespaces" {
  description = "List of namespaces allowed to send ingress traffic"
  type        = list(string)
  default     = []
}

variable "allowed_ports" {
  description = "List of TCP port numbers to allow from specified namespaces"
  type        = list(number)
  default     = []

  validation {
    condition     = alltrue([for p in var.allowed_ports : p > 0 && p <= 65535])
    error_message = "All ports must be between 1 and 65535."
  }
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
