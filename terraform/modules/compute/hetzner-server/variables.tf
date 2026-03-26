variable "name_prefix" {
  description = "Prefix applied to all resource names"
  type        = string
  default     = "grc"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "location" {
  description = "Hetzner datacenter location (e.g. nbg1, fsn1, hel1, ash)"
  type        = string
  default     = "nbg1"
}

variable "server_type" {
  description = "Hetzner server type (e.g. cx21, cx31, cpx11)"
  type        = string
  default     = "cx21"
}

variable "image" {
  description = "OS image for the server (e.g. ubuntu-22.04, debian-12)"
  type        = string
  default     = "ubuntu-22.04"
}

variable "ssh_public_key" {
  description = "SSH public key for server access"
  type        = string

  validation {
    condition     = length(var.ssh_public_key) > 0
    error_message = "ssh_public_key must not be empty."
  }
}

variable "firewall_ids" {
  description = "List of Hetzner firewall IDs to attach to the server"
  type        = list(number)
  default     = []
}

variable "enable_data_volume" {
  description = "Whether to create and attach an encrypted data volume"
  type        = bool
  default     = false
}

variable "data_volume_size_gb" {
  description = "Size of the data volume in GB (when enabled)"
  type        = number
  default     = 50

  validation {
    condition     = var.data_volume_size_gb >= 10 && var.data_volume_size_gb <= 10240
    error_message = "data_volume_size_gb must be between 10 and 10240."
  }
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
