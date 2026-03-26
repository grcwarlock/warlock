output "cpu_alert_ids" {
  description = "Map of droplet ID to CPU monitor alert ID"
  value       = { for k, v in digitalocean_monitor_alert.cpu : k => v.id }
}

output "memory_alert_ids" {
  description = "Map of droplet ID to memory monitor alert ID"
  value       = { for k, v in digitalocean_monitor_alert.memory : k => v.id }
}

output "uptime_check_ids" {
  description = "Map of droplet ID to uptime check ID"
  value       = { for k, v in digitalocean_uptime_check.main : k => v.id }
}
