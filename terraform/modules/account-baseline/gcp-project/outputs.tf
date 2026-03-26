output "audit_dataset_id" {
  description = "BigQuery dataset ID receiving audit log exports"
  value       = google_bigquery_dataset.audit_logs.dataset_id
}

output "audit_sink_name" {
  description = "Name of the Cloud Logging sink that writes audit logs to BigQuery"
  value       = google_logging_project_sink.audit.name
}
