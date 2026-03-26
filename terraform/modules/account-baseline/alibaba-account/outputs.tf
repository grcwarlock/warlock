output "trail_name" {
  description = "Name of the ActionTrail baseline trail"
  value       = alicloud_actiontrail_trail.main.trail_name
}

output "password_policy_applied" {
  description = "Whether the RAM password policy was applied (always true when module is used)"
  value       = true
}
