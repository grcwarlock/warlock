output "key_arn" {
  description = "ARN of the KMS key — use as kms_key_id on resources requiring encryption at rest (SC-28)"
  value       = aws_kms_key.main.arn
}

output "key_id" {
  description = "Key ID of the KMS key"
  value       = aws_kms_key.main.key_id
}

output "key_alias_arn" {
  description = "ARN of the KMS alias"
  value       = aws_kms_alias.main.arn
}

output "key_alias_name" {
  description = "Name of the KMS alias (e.g. alias/warlock-baseline)"
  value       = aws_kms_alias.main.name
}
