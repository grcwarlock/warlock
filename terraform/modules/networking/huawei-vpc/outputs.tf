output "vpc_id" {
  description = "ID of the Huawei Cloud VPC"
  value       = huaweicloud_vpc.main.id
}

output "subnet_ids" {
  description = "Map of subnet IDs keyed by index"
  value       = { for k, v in huaweicloud_vpc_subnet.main : k => v.id }
}

output "security_group_id" {
  description = "ID of the default security group with deny-all baseline"
  value       = huaweicloud_networking_secgroup.main.id
}
