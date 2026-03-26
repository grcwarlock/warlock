output "instance_id" {
  description = "ID of the Scaleway instance server"
  value       = scaleway_instance_server.main.id
}

output "private_ip" {
  description = "Private IPv4 address of the instance"
  value       = try(scaleway_instance_server.main.private_ips[0], "")
}

output "public_ip" {
  description = "Public IPv4 address of the instance (empty if public IP is disabled)"
  value       = var.enable_public_ip ? scaleway_instance_ip.public[0].address : ""
}
