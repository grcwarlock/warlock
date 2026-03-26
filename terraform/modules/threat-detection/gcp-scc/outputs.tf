output "notification_config_name" {
  description = "Fully-qualified name of the SCC notification config"
  value       = google_scc_notification_config.main.name
}

output "pubsub_topic_id" {
  description = "Fully-qualified resource ID of the Pub/Sub topic receiving SCC findings"
  value       = google_pubsub_topic.scc_findings.id
}
