output "auditor_role_arn" {
  value = aws_iam_role.grc_auditor.arn
}

output "security_alerts_topic_arn" {
  value = aws_sns_topic.security_alerts.arn
}
