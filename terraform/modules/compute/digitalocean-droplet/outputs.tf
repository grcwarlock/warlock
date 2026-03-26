output "droplet_id" {
  description = "ID of the DigitalOcean Droplet"
  value       = digitalocean_droplet.main.id
}

output "ipv4_address" {
  description = "Public IPv4 address of the Droplet"
  value       = digitalocean_droplet.main.ipv4_address
}

output "ipv4_address_private" {
  description = "Private IPv4 address of the Droplet (VPC)"
  value       = digitalocean_droplet.main.ipv4_address_private
}
