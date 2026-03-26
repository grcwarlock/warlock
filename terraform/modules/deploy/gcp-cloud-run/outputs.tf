###############################################################################
# Outputs — Warlock GCP Cloud Run Deployment
###############################################################################

output "api_url" {
  description = "URL of the Warlock API Cloud Run service"
  value       = google_cloud_run_v2_service.api.uri
}

output "sql_connection_name" {
  description = "Cloud SQL instance connection name (project:region:instance)"
  value       = google_sql_database_instance.warlock.connection_name
}

output "sql_ip_address" {
  description = "Cloud SQL private IP address"
  value       = google_sql_database_instance.warlock.private_ip_address
}

output "redis_host" {
  description = "Memorystore Redis host"
  value       = google_redis_instance.warlock.host
}

output "redis_port" {
  description = "Memorystore Redis port"
  value       = google_redis_instance.warlock.port
}
