variable "account_id" {
  description = "Cloudflare Account ID"
  type        = string

  validation {
    condition     = length(var.account_id) == 32
    error_message = "account_id must be a 32-character Cloudflare account identifier."
  }
}

variable "bucket_name" {
  description = "Name of the R2 bucket"
  type        = string

  validation {
    condition     = length(var.bucket_name) >= 3 && length(var.bucket_name) <= 63
    error_message = "bucket_name must be between 3 and 63 characters."
  }
}

variable "location" {
  description = "R2 bucket location hint (auto, wnam, enam, weur, eeur, apac)"
  type        = string
  default     = "auto"

  validation {
    condition     = contains(["auto", "wnam", "enam", "weur", "eeur", "apac"], var.location)
    error_message = "location must be one of: auto, wnam, enam, weur, eeur, apac."
  }
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
