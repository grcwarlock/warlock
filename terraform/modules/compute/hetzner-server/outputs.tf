output "server_id" {
  description = "ID of the Hetzner Cloud server"
  value       = hcloud_server.main.id
}

output "ipv4_address" {
  description = "Public IPv4 address of the server"
  value       = hcloud_server.main.ipv4_address
}

output "ipv6_address" {
  description = "IPv6 address of the server"
  value       = hcloud_server.main.ipv6_address
}
