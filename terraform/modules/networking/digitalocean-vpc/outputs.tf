output "vpc_id" {
  description = "ID of the DigitalOcean VPC"
  value       = digitalocean_vpc.main.id
}

output "vpc_urn" {
  description = "URN of the DigitalOcean VPC"
  value       = digitalocean_vpc.main.urn
}

output "firewall_id" {
  description = "ID of the DigitalOcean Firewall"
  value       = digitalocean_firewall.main.id
}
