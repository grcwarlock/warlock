###############################################################################
# Outputs — Warlock Azure Container Apps Deployment
###############################################################################

output "api_fqdn" {
  description = "FQDN of the Warlock API container app"
  value       = azurerm_container_app.api.ingress[0].fqdn
}

output "api_url" {
  description = "Full HTTPS URL of the Warlock API"
  value       = "https://${azurerm_container_app.api.ingress[0].fqdn}"
}

output "db_fqdn" {
  description = "PostgreSQL Flexible Server FQDN"
  value       = azurerm_postgresql_flexible_server.warlock.fqdn
}

output "redis_hostname" {
  description = "Redis Cache hostname"
  value       = azurerm_redis_cache.warlock.hostname
}
