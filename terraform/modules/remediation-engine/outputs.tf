output "lambda_function_arn" {
  description = "ARN of the remediation engine Lambda function"
  value       = aws_lambda_function.remediation_engine.arn
}

output "lambda_function_url" {
  description = "Function URL for the remediation engine Lambda (AWS_IAM auth)"
  value       = aws_lambda_function_url.remediation_engine.function_url
}

output "ssm_tfc_token_name" {
  description = "SSM parameter name storing the Terraform Cloud API token"
  value       = aws_ssm_parameter.tfc_token.name
}

output "ssm_warlock_token_name" {
  description = "SSM parameter name storing the Warlock API token"
  value       = aws_ssm_parameter.warlock_api_token.name
}

output "log_group_name" {
  description = "Name of the CloudWatch log group for the remediation engine Lambda"
  value       = aws_cloudwatch_log_group.remediation_lambda.name
}
