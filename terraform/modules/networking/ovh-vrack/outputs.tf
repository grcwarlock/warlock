output "network_id" {
  description = "ID of the OVH private network"
  value       = ovh_cloud_project_network_private.main.id
}

output "subnet_id" {
  description = "ID of the private subnet"
  value       = ovh_cloud_project_network_private_subnet.main.id
}
