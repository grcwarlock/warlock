output "lambda_function_arn" {
  description = "ARN of the drift detection Lambda function"
  value       = aws_lambda_function.drift_detector.arn
}

output "lambda_function_name" {
  description = "Name of the drift detection Lambda function"
  value       = aws_lambda_function.drift_detector.function_name
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic that receives drift findings"
  value       = aws_sns_topic.drift_findings.arn
}

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch log group for the drift detector Lambda"
  value       = aws_cloudwatch_log_group.drift_lambda.name
}

output "event_rule_arn" {
  description = "ARN of the EventBridge rule that triggers drift detection on schedule"
  value       = aws_cloudwatch_event_rule.drift_schedule.arn
}
