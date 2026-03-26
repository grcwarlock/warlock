output "securityhub_arn" {
  description = "ARN of the Security Hub account resource"
  value       = aws_securityhub_account.main.arn
}

output "cis_subscription_arn" {
  description = "ARN of the CIS AWS Foundations standard subscription (null if disabled)"
  value       = length(aws_securityhub_standards_subscription.cis) > 0 ? aws_securityhub_standards_subscription.cis[0].id : null
}

output "foundational_subscription_arn" {
  description = "ARN of the AWS Foundational Security Best Practices subscription (null if disabled)"
  value       = length(aws_securityhub_standards_subscription.foundational) > 0 ? aws_securityhub_standards_subscription.foundational[0].id : null
}
