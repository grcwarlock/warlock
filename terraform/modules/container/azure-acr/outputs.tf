output "acr_id" {
  description = "Resource ID of the Azure Container Registry"
  value       = azurerm_container_registry.main.id
}

output "acr_login_server" {
  description = "Login server URL of the ACR — use for docker login"
  value       = azurerm_container_registry.main.login_server
}

output "acr_admin_username" {
  description = "Admin username of the ACR (empty when admin is disabled, as recommended)"
  value       = azurerm_container_registry.main.admin_username
}
