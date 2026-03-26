output "key_id" {
  description = "ID of the Huawei Cloud KMS key"
  value       = huaweicloud_kms_key.main.id
}

output "key_alias" {
  description = "Alias of the Huawei Cloud KMS key"
  value       = huaweicloud_kms_key.main.key_alias
}
