variable "name_prefix" {
  description = "Prefix applied to resource names in this module"
  type        = string
  default     = "warlock"

  validation {
    condition     = length(var.name_prefix) >= 2 && length(var.name_prefix) <= 20
    error_message = "name_prefix must be between 2 and 20 characters."
  }
}

variable "finding_publishing_frequency" {
  description = "How often GuardDuty publishes findings: FIFTEEN_MINUTES, ONE_HOUR, or SIX_HOURS"
  type        = string
  default     = "SIX_HOURS"

  validation {
    condition     = contains(["FIFTEEN_MINUTES", "ONE_HOUR", "SIX_HOURS"], var.finding_publishing_frequency)
    error_message = "finding_publishing_frequency must be FIFTEEN_MINUTES, ONE_HOUR, or SIX_HOURS."
  }
}

variable "enable_s3_protection" {
  description = "Enable GuardDuty S3 Protection (detects malicious S3 access patterns)"
  type        = bool
  default     = true
}

variable "enable_eks_protection" {
  description = "Enable GuardDuty EKS Audit Log Monitoring (detects threats against Kubernetes)"
  type        = bool
  default     = true
}

variable "enable_malware_protection" {
  description = "Enable GuardDuty Malware Protection for EC2 EBS volumes"
  type        = bool
  default     = true
}

variable "auto_enable_org_members" {
  description = "How to auto-enable GuardDuty for new organization accounts: ALL, NEW, or NONE"
  type        = string
  default     = "NEW"

  validation {
    condition     = contains(["ALL", "NEW", "NONE"], var.auto_enable_org_members)
    error_message = "auto_enable_org_members must be ALL, NEW, or NONE."
  }
}

variable "organization_admin_account_id" {
  description = "AWS account ID to designate as the GuardDuty delegated administrator. Set to null to skip delegation."
  type        = string
  default     = null
}

variable "findings_s3_bucket_arn" {
  description = "ARN of an S3 bucket to receive GuardDuty findings exports. Set to null to skip."
  type        = string
  default     = null
}

variable "findings_kms_key_arn" {
  description = "ARN of a KMS key used to encrypt GuardDuty findings in S3. Required when findings_s3_bucket_arn is set."
  type        = string
  default     = null
}

variable "tags" {
  description = "Map of tags applied to all resources in this module"
  type        = map(string)
  default     = {}
}
