output "bucket_id" {
  description = "ID (name) of the Alibaba Cloud OSS bucket"
  value       = alicloud_oss_bucket.main.id
}

output "bucket_domain_name" {
  description = "Internal domain name of the OSS bucket"
  value       = alicloud_oss_bucket.main.intranet_endpoint
}
