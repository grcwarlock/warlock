output "role_arn" {
  description = "ARN of the IAM role for Warlock cross-account connector access"
  value       = aws_iam_role.warlock_connector.arn
}

output "kms_key_arn" {
  description = "ARN of the KMS key used to encrypt connector credentials"
  value       = aws_kms_key.connector_credentials.arn
}

output "kms_key_alias" {
  description = "Alias of the KMS key used to encrypt connector credentials"
  value       = aws_kms_alias.connector_credentials.name
}

output "log_group_name" {
  description = "Name of the CloudWatch log group for connector audit logs"
  value       = aws_cloudwatch_log_group.connector_audit.name
}

output "ssm_parameter_arns" {
  description = "Map of connector name to SSM parameter ARN for stored API keys"
  value       = { for k, v in aws_ssm_parameter.connector_api_key : k => v.arn }
}
