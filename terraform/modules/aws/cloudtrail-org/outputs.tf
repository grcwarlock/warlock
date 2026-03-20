output "trail_arn" {
  description = "ARN of the organization CloudTrail trail"
  value       = aws_cloudtrail.org.arn
}

output "trail_home_region" {
  description = "Home region of the organization CloudTrail trail"
  value       = aws_cloudtrail.org.home_region
}

output "trail_bucket_arn" {
  description = "ARN of the S3 bucket receiving organization trail logs"
  value       = aws_s3_bucket.org_trail.arn
}

output "trail_bucket_id" {
  description = "Name (ID) of the S3 bucket receiving organization trail logs"
  value       = aws_s3_bucket.org_trail.id
}

output "cloudwatch_log_group_arn" {
  description = "ARN of the CloudWatch log group receiving near-real-time CloudTrail events"
  value       = aws_cloudwatch_log_group.org_trail.arn
}

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch log group"
  value       = aws_cloudwatch_log_group.org_trail.name
}

output "sns_topic_arn" {
  description = "ARN of the CloudTrail alerts SNS topic (null if create_sns_topic is false)"
  value       = length(aws_sns_topic.cloudtrail_alerts) > 0 ? aws_sns_topic.cloudtrail_alerts[0].arn : null
}
