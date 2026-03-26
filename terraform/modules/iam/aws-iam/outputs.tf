output "auditor_role_arn" {
  description = "ARN of the GRC auditor IAM role"
  value       = aws_iam_role.grc_auditor.arn
}

output "security_alerts_topic_arn" {
  description = "ARN of the SNS topic receiving security alerts (root account usage, etc.)"
  value       = aws_sns_topic.security_alerts.arn
}
