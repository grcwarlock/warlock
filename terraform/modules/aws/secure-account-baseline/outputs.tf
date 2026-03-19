output "cloudtrail_arn" {
  value = aws_cloudtrail.main.arn
}

output "log_bucket_arn" {
  value = aws_s3_bucket.audit_logs.arn
}

output "guardduty_detector_id" {
  value = var.enable_guardduty ? aws_guardduty_detector.main[0].id : ""
}
