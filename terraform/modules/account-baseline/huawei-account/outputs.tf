output "tracker_name" {
  description = "Name of the CTS baseline tracker"
  value       = huaweicloud_cts_tracker.main.id
}

output "password_policy_applied" {
  description = "Whether the IAM password policy was applied (always true when module is used)"
  value       = true
}
