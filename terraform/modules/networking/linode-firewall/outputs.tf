output "firewall_id" {
  description = "ID of the Linode Cloud Firewall"
  value       = linode_firewall.main.id
}
