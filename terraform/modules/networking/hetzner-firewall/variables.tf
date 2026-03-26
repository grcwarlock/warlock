variable "name_prefix" {
  description = "Prefix applied to all resource names"
  type        = string
  default     = "grc"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "allowed_inbound" {
  description = "List of inbound firewall rules. Each item specifies port, protocol, and source_ips."
  type = list(object({
    port       = number
    protocol   = string
    source_ips = list(string)
  }))
  default = []

  validation {
    condition     = alltrue([for r in var.allowed_inbound : contains(["tcp", "udp", "icmp", "gre", "esp"], r.protocol)])
    error_message = "Each rule protocol must be one of: tcp, udp, icmp, gre, esp."
  }
}

variable "server_ids" {
  description = "List of Hetzner server IDs to attach the firewall to. Empty = no attachment."
  type        = list(number)
  default     = []
}

variable "labels" {
  description = "Map of labels applied to all resources"
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
