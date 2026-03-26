output "cluster_id" {
  description = "ID of the DigitalOcean database cluster"
  value       = digitalocean_database_cluster.main.id
}

output "host" {
  description = "Hostname of the database cluster"
  value       = digitalocean_database_cluster.main.host
}

output "port" {
  description = "Port of the database cluster"
  value       = digitalocean_database_cluster.main.port
}

output "uri" {
  description = "Full connection URI for the database cluster"
  value       = digitalocean_database_cluster.main.uri
  sensitive   = true
}
