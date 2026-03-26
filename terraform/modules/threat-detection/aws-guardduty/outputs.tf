output "detector_id" {
  description = "ID of the GuardDuty detector in this account/region"
  value       = aws_guardduty_detector.main.id
}

output "detector_arn" {
  description = "ARN of the GuardDuty detector"
  value       = aws_guardduty_detector.main.arn
}

output "publishing_destination_id" {
  description = "ID of the S3 publishing destination (null if not configured)"
  value       = length(aws_guardduty_publishing_destination.s3) > 0 ? aws_guardduty_publishing_destination.s3[0].id : null
}
