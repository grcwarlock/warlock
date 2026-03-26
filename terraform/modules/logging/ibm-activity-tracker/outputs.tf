output "instance_id" {
  description = "ID of the Activity Tracker instance"
  value       = ibm_resource_instance.activity_tracker.id
}

output "target_id" {
  description = "ID of the Activity Tracker COS target"
  value       = ibm_atracker_target.cos.id
}

output "route_id" {
  description = "ID of the Activity Tracker route"
  value       = ibm_atracker_route.main.id
}
