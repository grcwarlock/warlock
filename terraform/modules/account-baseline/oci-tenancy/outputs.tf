output "log_group_id" {
  description = "OCID of the tenancy audit log group"
  value       = oci_logging_log_group.audit.id
}

output "vault_id" {
  description = "OCID of the tenancy KMS vault"
  value       = oci_kms_vault.tenancy.id
}

output "key_id" {
  description = "OCID of the tenancy master encryption key"
  value       = oci_kms_key.tenancy.id
}
