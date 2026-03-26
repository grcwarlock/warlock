output "bucket_name" {
  description = "Name of the DigitalOcean Spaces bucket"
  value       = digitalocean_spaces_bucket.main.name
}

output "bucket_urn" {
  description = "URN of the DigitalOcean Spaces bucket"
  value       = digitalocean_spaces_bucket.main.urn
}

output "bucket_domain_name" {
  description = "FQDN to access the Spaces bucket"
  value       = digitalocean_spaces_bucket.main.bucket_domain_name
}
