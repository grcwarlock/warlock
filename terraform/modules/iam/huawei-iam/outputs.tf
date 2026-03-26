output "group_id" {
  description = "ID of the Huawei Cloud IAM auditor group"
  value       = huaweicloud_identity_group.auditor.id
}

output "role_id" {
  description = "ID of the Huawei Cloud IAM auditor role"
  value       = huaweicloud_identity_role.auditor.id
}
