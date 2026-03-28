output "api_endpoint" {
  description = "Full API endpoint URL for the physical security panel"
  value       = "${local.vendor_config[var.vendor].protocol}://${var.panel_endpoint}:${local.api_port}"
}

output "secret_path" {
  description = "Path to the stored panel credentials (Secrets Manager name or SSM parameter name)"
  value = var.secret_backend == "aws_sm" ? (
    length(aws_secretsmanager_secret.panel_credentials) > 0 ? aws_secretsmanager_secret.panel_credentials[0].name : null
    ) : (
    length(aws_ssm_parameter.panel_api_key) > 0 ? aws_ssm_parameter.panel_api_key[0].name : null
  )
}

output "security_group_id" {
  description = "Security group ID for Warlock-to-panel network access"
  value       = aws_security_group.warlock_panel_access.id
}

output "endpoint_parameter_name" {
  description = "SSM parameter name storing the panel endpoint configuration"
  value       = aws_ssm_parameter.panel_endpoint.name
}

output "log_group_name" {
  description = "CloudWatch log group for physical security connector audit logs"
  value       = aws_cloudwatch_log_group.physec_audit.name
}
