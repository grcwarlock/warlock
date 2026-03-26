output "log_group_id" {
  description = "OCID of the OCI Logging log group"
  value       = oci_logging_log_group.audit.id
}

output "log_id" {
  description = "OCID of the audit service log"
  value       = oci_logging_log.audit.id
}
