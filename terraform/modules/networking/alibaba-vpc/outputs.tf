output "vpc_id" {
  description = "ID of the Alibaba Cloud VPC"
  value       = alicloud_vpc.main.id
}

output "vswitch_ids" {
  description = "Map of VSwitch IDs keyed by index"
  value       = { for k, v in alicloud_vswitch.main : k => v.id }
}

output "security_group_id" {
  description = "ID of the default security group with deny-all baseline"
  value       = alicloud_security_group.main.id
}
