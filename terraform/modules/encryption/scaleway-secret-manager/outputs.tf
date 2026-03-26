output "secret_id" {
  description = "ID of the Scaleway secret"
  value       = scaleway_secret.main.id
}

output "secret_version_id" {
  description = "ID of the Scaleway secret version"
  value       = scaleway_secret_version.main.id
}
