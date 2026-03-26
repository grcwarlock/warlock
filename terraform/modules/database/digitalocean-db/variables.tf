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
  description = "DigitalOcean region for the database cluster"
  type        = string
  default     = "nyc3"
}

variable "engine" {
  description = "Database engine (pg, mysql, redis, mongodb)"
  type        = string
  default     = "pg"

  validation {
    condition     = contains(["pg", "mysql", "redis", "mongodb"], var.engine)
    error_message = "engine must be one of: pg, mysql, redis, mongodb."
  }
}

variable "engine_version" {
  description = "Database engine version"
  type        = string
  default     = "15"
}

variable "size" {
  description = "Database cluster node size"
  type        = string
  default     = "db-s-1vcpu-2gb"
}

variable "node_count" {
  description = "Number of database nodes in the cluster"
  type        = number
  default     = 1

  validation {
    condition     = var.node_count >= 1 && var.node_count <= 5
    error_message = "node_count must be between 1 and 5."
  }
}

variable "vpc_uuid" {
  description = "UUID of the VPC for private networking"
  type        = string
  default     = null
}

variable "trusted_source_ids" {
  description = "List of Droplet IDs allowed to connect to the database"
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "List of tag names applied to the database cluster"
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
