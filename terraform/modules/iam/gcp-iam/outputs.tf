output "auditor_role_id" {
  description = "Fully-qualified ID of the custom auditor IAM role"
  value       = google_project_iam_custom_role.auditor.id
}

output "auditor_role_name" {
  description = "Short name of the custom auditor IAM role"
  value       = google_project_iam_custom_role.auditor.role_id
}
