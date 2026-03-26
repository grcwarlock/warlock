output "vpc_id" {
  description = "ID of the IBM Cloud VPC"
  value       = ibm_is_vpc.main.id
}

output "subnet_ids" {
  description = "Map of zone to subnet ID"
  value       = { for k, v in ibm_is_subnet.zones : k => v.id }
}

output "security_group_id" {
  description = "ID of the VPC security group"
  value       = ibm_is_security_group.main.id
}
