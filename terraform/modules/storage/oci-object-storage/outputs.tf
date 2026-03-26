output "bucket_name" {
  description = "Name of the Object Storage bucket"
  value       = oci_objectstorage_bucket.main.name
}

output "bucket_id" {
  description = "OCID of the Object Storage bucket"
  value       = oci_objectstorage_bucket.main.bucket_id
}
