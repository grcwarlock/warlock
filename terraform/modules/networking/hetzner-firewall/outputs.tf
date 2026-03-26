output "firewall_id" {
  description = "ID of the Hetzner Cloud firewall"
  value       = hcloud_firewall.main.id
}
