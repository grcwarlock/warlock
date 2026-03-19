output "cloudtrail_arn" {
  description = "ARN of the CloudTrail trail"
  value       = aws_cloudtrail.main.arn
}

output "log_bucket_arn" {
  description = "ARN of the S3 bucket storing CloudTrail audit logs"
  value       = aws_s3_bucket.audit_logs.arn
}

output "guardduty_detector_id" {
  description = "ID of the GuardDuty detector (empty string when GuardDuty is disabled)"
  value       = var.enable_guardduty ? aws_guardduty_detector.main[0].id : ""
}

# T-1: KMS key ARN output (null when caller supplied their own key)
output "cloudtrail_kms_key_arn" {
  description = "ARN of the KMS key used to encrypt CloudTrail logs. Null when var.kms_key_id was provided by the caller."
  value       = length(aws_kms_key.cloudtrail) > 0 ? aws_kms_key.cloudtrail[0].arn : null
}

# T-13: CloudWatch log group output
output "cloudtrail_log_group_name" {
  description = "Name of the CloudWatch log group receiving CloudTrail events"
  value       = aws_cloudwatch_log_group.cloudtrail.name
}
