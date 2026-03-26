output "function_arn" {
  description = "ARN of the Lambda function"
  value       = aws_lambda_function.main.arn
}

output "function_name" {
  description = "Name of the Lambda function"
  value       = aws_lambda_function.main.function_name
}

output "invoke_arn" {
  description = "Invoke ARN of the Lambda function (for API Gateway integration)"
  value       = aws_lambda_function.main.invoke_arn
}

output "log_group_arn" {
  description = "ARN of the CloudWatch log group for Lambda logs"
  value       = aws_cloudwatch_log_group.lambda.arn
}
