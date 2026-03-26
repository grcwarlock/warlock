output "function_uri" {
  description = "HTTPS URI of the Cloud Function"
  value       = google_cloudfunctions2_function.main.service_config[0].uri
}

output "function_name" {
  description = "Name of the Cloud Function"
  value       = google_cloudfunctions2_function.main.name
}

output "service_account_email" {
  description = "Service account email used by the Cloud Function"
  value       = google_cloudfunctions2_function.main.service_config[0].service_account_email
}
