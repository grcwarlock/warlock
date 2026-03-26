output "instance_id" {
  description = "ID of the Linode instance"
  value       = linode_instance.main.id
}

output "ip_address" {
  description = "Public IPv4 address of the Linode instance"
  value       = linode_instance.main.ip_address
}

output "private_ip_address" {
  description = "Private IPv4 address of the Linode instance"
  value       = linode_instance.main.private_ip_address
}
