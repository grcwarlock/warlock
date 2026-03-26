output "scheduler_job_id" {
  description = "Fully-qualified resource ID of the Cloud Scheduler job"
  value       = google_cloud_scheduler_job.drift_trigger.id
}

output "function_uri" {
  description = "HTTPS URI of the drift detection Cloud Function"
  value       = google_cloudfunctions2_function.drift_checker.service_config[0].uri
}
