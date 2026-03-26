variable "name_prefix" {
  description = "Prefix applied to all resource names"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "allowed_inbound" {
  description = "List of inbound firewall rules to allow"
  type = list(object({
    label          = string
    ports          = string
    protocol       = string
    ipv4_addresses = list(string)
    ipv6_addresses = optional(list(string), [])
  }))
  default = []
}

variable "linode_ids" {
  description = "List of Linode instance IDs to attach to the firewall"
  type        = list(number)
  default     = []
}

variable "tags" {
  description = "List of tag names applied to the firewall"
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
