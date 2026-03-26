output "trail_name" {
  description = "Name of the ActionTrail trail"
  value       = alicloud_actiontrail_trail.main.trail_name
}

output "bucket_name" {
  description = "Name of the OSS bucket storing ActionTrail logs"
  value       = alicloud_oss_bucket.trail.id
}
