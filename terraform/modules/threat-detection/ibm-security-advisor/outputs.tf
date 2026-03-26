output "scc_instance_id" {
  description = "ID of the Security & Compliance Center instance"
  value       = ibm_resource_instance.scc.id
}

output "profile_attachment_id" {
  description = "ID of the SCC profile attachment"
  value       = ibm_scc_profile_attachment.main.attachment_id
}
