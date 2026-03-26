output "app_id" {
  description = "ID of the Cloudflare Access application"
  value       = cloudflare_access_application.main.id
}

output "app_aud" {
  description = "Application Audience (AUD) tag for JWT verification"
  value       = cloudflare_access_application.main.aud
}
