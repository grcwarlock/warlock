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
  description = "DigitalOcean region for the VPC"
  type        = string
  default     = "nyc3"
}

variable "ip_range" {
  description = "Private IP range for the VPC in CIDR notation"
  type        = string
  default     = "10.10.10.0/24"

  validation {
    condition     = can(cidrhost(var.ip_range, 0))
    error_message = "ip_range must be a valid CIDR block."
  }
}

variable "allowed_inbound_ports" {
  description = "List of inbound firewall rules to allow"
  type = list(object({
    protocol         = string
    port_range       = string
    source_addresses = list(string)
  }))
  default = []
}

variable "droplet_ids" {
  description = "List of Droplet IDs to attach to the firewall"
  type        = list(number)
  default     = []
}

variable "tags" {
  description = "List of tag names applied to firewall resources"
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
