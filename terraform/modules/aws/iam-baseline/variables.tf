variable "auditor_principal_arn" {
  description = "ARN of the principal allowed to assume the audit role"
  type        = string
}

variable "cloudtrail_log_group" {
  description = "CloudWatch log group name for CloudTrail"
  type        = string
}

variable "tags" {
  type    = map(string)
  default = {}
}
