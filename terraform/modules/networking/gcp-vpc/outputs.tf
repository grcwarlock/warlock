output "network_id" {
  description = "Numeric ID of the GCP VPC network"
  value       = google_compute_network.main.id
}

output "network_self_link" {
  description = "Self-link URI of the GCP VPC network"
  value       = google_compute_network.main.self_link
}

output "subnet_id" {
  description = "Numeric ID of the primary subnet"
  value       = google_compute_subnetwork.main.id
}

output "subnet_self_link" {
  description = "Self-link URI of the primary subnet"
  value       = google_compute_subnetwork.main.self_link
}

output "router_id" {
  description = "ID of the Cloud Router (null if Cloud NAT is disabled)"
  value       = length(google_compute_router.main) > 0 ? google_compute_router.main[0].id : null
}
