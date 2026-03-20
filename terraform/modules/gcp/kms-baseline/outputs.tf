output "keyring_id" {
  description = "Fully-qualified resource ID of the Cloud KMS keyring"
  value       = google_kms_key_ring.main.id
}

output "keyring_name" {
  description = "Short name of the Cloud KMS keyring"
  value       = google_kms_key_ring.main.name
}

output "crypto_key_id" {
  description = "Fully-qualified resource ID of the crypto key — use as default_kms_key_name for CMEK-enabled resources (SC-28)"
  value       = google_kms_crypto_key.main.id
}

output "crypto_key_name" {
  description = "Short name of the crypto key"
  value       = google_kms_crypto_key.main.name
}

output "cmek_bucket_name" {
  description = "Name of the CMEK-encrypted GCS bucket (null if create_cmek_bucket is false)"
  value       = length(google_storage_bucket.cmek_example) > 0 ? google_storage_bucket.cmek_example[0].name : null
}
