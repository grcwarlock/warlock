output "audit_dataset_id" {
  value = google_bigquery_dataset.audit_logs.dataset_id
}

output "audit_sink_name" {
  value = google_logging_project_sink.audit.name
}
