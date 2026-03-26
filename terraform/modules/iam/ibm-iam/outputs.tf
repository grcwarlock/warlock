output "access_group_id" {
  description = "ID of the auditor IAM access group"
  value       = ibm_iam_access_group.auditors.id
}
