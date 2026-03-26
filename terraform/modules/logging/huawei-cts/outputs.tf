output "tracker_name" {
  description = "Name of the CTS tracker"
  value       = huaweicloud_cts_tracker.main.id
}

output "bucket_name" {
  description = "Name of the OBS bucket storing CTS logs"
  value       = huaweicloud_obs_bucket.trail.bucket
}
