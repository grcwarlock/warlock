output "service_account_email" {
  description = "Email of the Warlock connector service account"
  value       = google_service_account.warlock_connector.email
}

output "service_account_id" {
  description = "Fully-qualified ID of the Warlock connector service account"
  value       = google_service_account.warlock_connector.id
}

output "workload_identity_pool" {
  description = "Name of the workload identity pool for keyless authentication"
  value       = var.create_workload_identity_pool ? google_iam_workload_identity_pool.warlock[0].name : null
}

output "workload_identity_pool_provider_aws" {
  description = "Name of the AWS workload identity pool provider (null if not created)"
  value       = var.create_workload_identity_pool && var.warlock_aws_account_id != null ? google_iam_workload_identity_pool_provider.warlock_aws[0].name : null
}

output "secret_ids" {
  description = "Map of connector name to Secret Manager secret ID"
  value       = { for k, v in google_secret_manager_secret.connector_tokens : k => v.secret_id }
}
