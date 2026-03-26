output "app_id" {
  description = "ID of the DigitalOcean App"
  value       = digitalocean_app.warlock.id
}

output "live_url" {
  description = "Live URL of the deployed application"
  value       = digitalocean_app.warlock.live_url
}

output "default_ingress" {
  description = "Default ingress URL for the application"
  value       = digitalocean_app.warlock.default_ingress
}
