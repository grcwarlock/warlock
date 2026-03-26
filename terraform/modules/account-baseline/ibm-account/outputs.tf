output "activity_tracker_id" {
  description = "ID of the Activity Tracker instance"
  value       = ibm_resource_instance.activity_tracker.id
}

output "cos_instance_id" {
  description = "ID of the account COS instance"
  value       = ibm_resource_instance.cos.id
}

output "cos_bucket_name" {
  description = "Name of the account data COS bucket"
  value       = ibm_cos_bucket.account_data.bucket_name
}
