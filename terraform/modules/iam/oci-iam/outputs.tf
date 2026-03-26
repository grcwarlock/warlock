output "compartment_id" {
  description = "OCID of the newly created workload compartment"
  value       = oci_identity_compartment.workload.id
}

output "group_id" {
  description = "OCID of the auditor IAM group"
  value       = oci_identity_group.auditors.id
}

output "policy_id" {
  description = "OCID of the auditor read-only policy"
  value       = oci_identity_policy.auditor_readonly.id
}
