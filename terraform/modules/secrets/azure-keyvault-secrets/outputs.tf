output "secret_id" {
  description = "Resource ID of the Key Vault secret (includes version)"
  value       = azurerm_key_vault_secret.main.id
}

output "secret_version" {
  description = "Current version of the Key Vault secret"
  value       = azurerm_key_vault_secret.main.version
}

output "secret_versionless_id" {
  description = "Versionless resource ID of the Key Vault secret"
  value       = azurerm_key_vault_secret.main.versionless_id
}
