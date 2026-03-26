output "cockpit_id" {
  description = "ID of the Scaleway Cockpit instance"
  value       = scaleway_cockpit.main.id
}

output "grafana_url" {
  description = "URL of the Cockpit Grafana dashboard (use scaleway_cockpit_grafana data source for current URL)"
  value       = try(scaleway_cockpit.main.endpoints[0].grafana_url, "")
}
