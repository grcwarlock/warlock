output "secret_name" {
  description = "Fully-qualified resource name of the secret"
  value       = google_secret_manager_secret.main.name
}

output "secret_id" {
  description = "ID of the secret in Secret Manager"
  value       = google_secret_manager_secret.main.secret_id
}

output "secret_version_name" {
  description = "Fully-qualified resource name of the secret version"
  value       = google_secret_manager_secret_version.main.name
}
