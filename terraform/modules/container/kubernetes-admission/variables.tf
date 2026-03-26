variable "name_prefix" {
  description = "Prefix applied to all resource names"
  type        = string
  default     = "grc"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "policy_engine" {
  description = "Admission policy engine to deploy: gatekeeper or kyverno"
  type        = string
  default     = "gatekeeper"

  validation {
    condition     = contains(["gatekeeper", "kyverno"], var.policy_engine)
    error_message = "policy_engine must be one of: gatekeeper, kyverno."
  }
}

variable "chart_version" {
  description = "Helm chart version override. Null uses the module default."
  type        = string
  default     = null
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
