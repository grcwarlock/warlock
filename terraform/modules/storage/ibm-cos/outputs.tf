output "bucket_crn" {
  description = "CRN of the COS bucket"
  value       = ibm_cos_bucket.main.crn
}

output "bucket_name" {
  description = "Name of the COS bucket"
  value       = ibm_cos_bucket.main.bucket_name
}

output "cos_instance_id" {
  description = "ID of the Cloud Object Storage instance"
  value       = ibm_resource_instance.cos.id
}
