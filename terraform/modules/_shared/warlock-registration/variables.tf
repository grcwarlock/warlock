variable "enabled" {
  description = "Whether to POST evidence to the Warlock API"
  type        = bool
  default     = false
}

variable "api_endpoint" {
  description = "Warlock API base URL (e.g. https://warlock.example.com)"
  type        = string
  default     = ""
}

variable "api_token" {
  description = "Bearer token for Warlock API authentication"
  type        = string
  default     = ""
  sensitive   = true
}

variable "module_name" {
  description = "Domain-qualified module name (e.g. encryption/aws-kms)"
  type        = string
}

variable "resource_id" {
  description = "Cloud resource ID (ARN, Azure resource ID, GCP resource name)"
  type        = string
}

variable "control_ids" {
  description = "NIST 800-53 control IDs this module enforces (e.g. [\"SC-12\", \"SC-28\"])"
  type        = list(string)
}

variable "attributes" {
  description = "Key compliance attributes to report as evidence"
  type        = map(string)
  default     = {}
}

variable "remediation_id" {
  description = "Warlock remediation ID when triggered by closed-loop engine. Null = standalone provision."
  type        = string
  default     = null
}
