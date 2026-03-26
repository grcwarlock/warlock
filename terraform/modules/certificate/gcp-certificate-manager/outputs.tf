output "certificate_id" {
  description = "Fully-qualified resource ID of the managed SSL certificate"
  value       = google_certificate_manager_certificate.main.id
}

output "certificate_map_id" {
  description = "Fully-qualified resource ID of the certificate map"
  value       = google_certificate_manager_certificate_map.main.id
}
