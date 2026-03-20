output "key_vault_id" {
  description = "Resource ID of the Azure Key Vault"
  value       = azurerm_key_vault.main.id
}

output "key_vault_name" {
  description = "Name of the Azure Key Vault"
  value       = azurerm_key_vault.main.name
}

output "key_vault_uri" {
  description = "URI of the Azure Key Vault — use as vault_uri in application configurations"
  value       = azurerm_key_vault.main.vault_uri
}

output "private_endpoint_id" {
  description = "Resource ID of the private endpoint (null if not created)"
  value       = length(azurerm_private_endpoint.key_vault) > 0 ? azurerm_private_endpoint.key_vault[0].id : null
}
