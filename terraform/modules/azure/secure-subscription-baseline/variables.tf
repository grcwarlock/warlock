variable "name_prefix" {
  type    = string
  default = "grc"
}

variable "resource_group_name" {
  type    = string
  default = "rg-grc-security"
}

variable "location" {
  type    = string
  default = "eastus"
}

variable "storage_account_name" {
  type        = string
  description = "Globally unique storage account name"
}

variable "log_retention_days" {
  type    = number
  default = 365
}

variable "security_contact_email" {
  description = "Email address for Microsoft Defender for Cloud alerts"
  type        = string
}

variable "tags" {
  type    = map(string)
  default = {}
}
