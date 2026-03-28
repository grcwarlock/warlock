output "client_id" {
  description = "Application (client) ID of the Warlock connector service principal"
  value       = azuread_application.warlock_connector.client_id
}

output "tenant_id" {
  description = "Azure AD tenant ID"
  value       = data.azuread_client_config.current.tenant_id
}

output "key_vault_name" {
  description = "Name of the Key Vault storing connector credentials"
  value       = azurerm_key_vault.connector.name
}

output "key_vault_uri" {
  description = "URI of the Key Vault storing connector credentials"
  value       = azurerm_key_vault.connector.vault_uri
}

output "service_principal_object_id" {
  description = "Object ID of the Warlock connector service principal"
  value       = azuread_service_principal.warlock_connector.object_id
}

output "resource_group_name" {
  description = "Name of the resource group containing Warlock connector resources"
  value       = azurerm_resource_group.warlock.name
}
