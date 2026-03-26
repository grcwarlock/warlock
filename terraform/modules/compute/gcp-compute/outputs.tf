output "instance_id" {
  description = "Unique ID of the GCE instance"
  value       = google_compute_instance.main.instance_id
}

output "instance_self_link" {
  description = "Self-link of the GCE instance"
  value       = google_compute_instance.main.self_link
}

output "instance_internal_ip" {
  description = "Internal IP address of the GCE instance"
  value       = google_compute_instance.main.network_interface[0].network_ip
}
