output "certificate_id" {
  description = "Resource ID of the Key Vault certificate"
  value       = azurerm_key_vault_certificate.main.id
}

output "certificate_thumbprint" {
  description = "X.509 thumbprint of the certificate (hex-encoded SHA-1)"
  value       = azurerm_key_vault_certificate.main.thumbprint
}

output "certificate_secret_id" {
  description = "Secret ID URI for the certificate in Key Vault — use for App Gateway SSL binding"
  value       = azurerm_key_vault_certificate.main.secret_id
}
