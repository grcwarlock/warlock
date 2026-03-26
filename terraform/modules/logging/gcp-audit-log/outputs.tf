output "sink_name" {
  description = "Name of the GCP logging project sink"
  value       = google_logging_project_sink.audit_sink.name
}

output "dataset_id" {
  description = "BigQuery dataset ID used for audit log storage"
  value       = google_bigquery_dataset.audit_logs.dataset_id
}

output "dataset_self_link" {
  description = "Self-link of the BigQuery audit log dataset"
  value       = google_bigquery_dataset.audit_logs.self_link
}
