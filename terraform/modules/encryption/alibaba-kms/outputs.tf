output "key_id" {
  description = "ID of the Alibaba Cloud KMS key"
  value       = alicloud_kms_key.main.id
}

output "key_arn" {
  description = "ARN of the Alibaba Cloud KMS key"
  value       = alicloud_kms_key.main.arn
}
