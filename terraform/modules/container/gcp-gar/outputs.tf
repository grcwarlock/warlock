output "repository_id" {
  description = "Fully-qualified resource ID of the Artifact Registry repository"
  value       = google_artifact_registry_repository.main.id
}

output "repository_name" {
  description = "Short name of the Artifact Registry repository"
  value       = google_artifact_registry_repository.main.name
}
