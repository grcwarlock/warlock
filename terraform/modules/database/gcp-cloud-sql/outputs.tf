output "instance_name" {
  description = "Name of the Cloud SQL instance"
  value       = google_sql_database_instance.main.name
}

output "instance_connection_name" {
  description = "Connection name of the Cloud SQL instance (project:region:name)"
  value       = google_sql_database_instance.main.connection_name
}

output "instance_ip_address" {
  description = "First IP address of the Cloud SQL instance"
  value       = google_sql_database_instance.main.ip_address[0].ip_address
}
