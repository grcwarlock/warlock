output "instance_id" {
  description = "GUID of the Key Protect instance"
  value       = ibm_resource_instance.key_protect.guid
}

output "key_id" {
  description = "ID of the root encryption key"
  value       = ibm_kms_key.root.key_id
}

output "key_crn" {
  description = "CRN of the root encryption key"
  value       = ibm_kms_key.root.crn
}
