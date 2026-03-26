variable "project_id" {
  description = "GCP project ID where the KMS keyring and crypto key will be created"
  type        = string

  validation {
    condition     = length(var.project_id) > 0
    error_message = "project_id must not be empty."
  }
}

variable "project_number" {
  description = "GCP project number — required to construct the GCS service account for CMEK grants"
  type        = string

  validation {
    condition     = can(regex("^[0-9]+$", var.project_number))
    error_message = "project_number must be a numeric string."
  }
}

variable "name_prefix" {
  description = "Prefix applied to the keyring, crypto key, and any buckets created by this module"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "location" {
  description = "Cloud KMS location (e.g. global, us-central1, europe-west1)"
  type        = string
  default     = "global"

  validation {
    condition     = length(var.location) > 0
    error_message = "location must not be empty."
  }
}

variable "rotation_period" {
  description = "Automatic rotation period for the crypto key in seconds (e.g. 7776000 = 90 days). SC-12 requires regular rotation."
  type        = string
  default     = "7776000s" # 90 days

  validation {
    condition     = can(regex("^[0-9]+s$", var.rotation_period))
    error_message = "rotation_period must be a duration string ending in 's' (e.g. '7776000s' for 90 days)."
  }
}

variable "key_purpose" {
  description = "Purpose of the crypto key: ENCRYPT_DECRYPT (symmetric), ASYMMETRIC_SIGN, or ASYMMETRIC_DECRYPT"
  type        = string
  default     = "ENCRYPT_DECRYPT"

  validation {
    condition     = contains(["ENCRYPT_DECRYPT", "ASYMMETRIC_SIGN", "ASYMMETRIC_DECRYPT", "MAC"], var.key_purpose)
    error_message = "key_purpose must be one of: ENCRYPT_DECRYPT, ASYMMETRIC_SIGN, ASYMMETRIC_DECRYPT, MAC."
  }
}

variable "create_cmek_bucket" {
  description = "When true, create a GCS bucket encrypted with this CMEK key as a demonstration of SC-28"
  type        = bool
  default     = false
}

variable "key_admin_members" {
  description = "List of IAM members granted roles/cloudkms.admin on the keyring (e.g. ['serviceAccount:sa@project.iam.gserviceaccount.com'])"
  type        = list(string)
  default     = []
}

variable "encrypter_decrypter_members" {
  description = "List of IAM members granted roles/cloudkms.cryptoKeyEncrypterDecrypter on the crypto key"
  type        = list(string)
  default     = []
}

variable "labels" {
  description = "Map of GCP labels applied to all resources in this module"
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
