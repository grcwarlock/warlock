output "bucket_name" {
  description = "Name of the Scaleway object storage bucket"
  value       = scaleway_object_bucket.main.name
}

output "bucket_endpoint" {
  description = "Endpoint URL of the Scaleway object storage bucket"
  value       = scaleway_object_bucket.main.endpoint
}
