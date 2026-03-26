output "bucket_name" {
  description = "Label of the Linode Object Storage bucket"
  value       = linode_object_storage_bucket.main.label
}

output "hostname" {
  description = "Hostname for the Object Storage bucket"
  value       = linode_object_storage_bucket.main.hostname
}
