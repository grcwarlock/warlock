output "secret_path" {
  description = "Path to the stored connector secret (Vault path, Secrets Manager name, or env:// URI)"
  value       = local.secret_path
}

output "secret_backend" {
  description = "Secret backend in use (vault, aws_sm, or env)"
  value       = var.secret_backend
}

output "vault_policy_name" {
  description = "Name of the Vault read policy (null if not using Vault)"
  value       = local.use_vault ? vault_policy.connector_read[0].name : null
}

output "aws_secret_arn" {
  description = "ARN of the AWS Secrets Manager secret (null if not using aws_sm)"
  value       = local.use_aws_sm ? aws_secretsmanager_secret.connector[0].arn : null
}
