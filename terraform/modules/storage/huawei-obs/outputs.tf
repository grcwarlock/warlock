output "bucket_id" {
  description = "ID (name) of the Huawei Cloud OBS bucket"
  value       = huaweicloud_obs_bucket.main.id
}

output "bucket_domain_name" {
  description = "Domain name of the OBS bucket"
  value       = huaweicloud_obs_bucket.main.bucket_domain_name
}
