output "vault_id" {
  description = "OCID of the OCI KMS vault"
  value       = oci_kms_vault.main.id
}

output "key_id" {
  description = "OCID of the master encryption key"
  value       = oci_kms_key.main.id
}

output "vault_crypto_endpoint" {
  description = "Crypto endpoint of the vault for encrypt/decrypt operations"
  value       = oci_kms_vault.main.crypto_endpoint
}
