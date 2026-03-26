variable "extra_tags" {
  description = "User-supplied tags/labels to merge with Warlock standard tags"
  type        = map(string)
  default     = {}
}

variable "module_name" {
  description = "Domain-qualified module name (e.g. encryption/aws-kms)"
  type        = string
}

variable "remediation_id" {
  description = "Warlock remediation ID (null = standalone)"
  type        = string
  default     = null
}
