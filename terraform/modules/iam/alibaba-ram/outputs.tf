output "role_arn" {
  description = "ARN of the Alibaba Cloud RAM auditor role"
  value       = alicloud_ram_role.auditor.arn
}

output "role_name" {
  description = "Name of the Alibaba Cloud RAM auditor role"
  value       = alicloud_ram_role.auditor.name
}

output "policy_name" {
  description = "Name of the read-only RAM policy"
  value       = alicloud_ram_policy.read_only.policy_name
}
