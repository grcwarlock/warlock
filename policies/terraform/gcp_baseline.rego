package terraform.gcp

import rego.v1

# Terraform plan-time compliance for GCP resources

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_storage_bucket"
	not resource.change.after.uniform_bucket_level_access
	msg := sprintf("GCS bucket '%s' must use uniform bucket-level access [AC-3]", [resource.name])
}

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_compute_firewall"
	resource.change.after.direction == "INGRESS"
	resource.change.after.source_ranges[_] == "0.0.0.0/0"
	some allow in resource.change.after.allow
	allow.ports[_] == "22"
	msg := sprintf("Firewall '%s' allows SSH from 0.0.0.0/0 [SC-7]", [resource.name])
}

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_sql_database_instance"
	not resource.change.after.settings[0].ip_configuration[0].require_ssl
	msg := sprintf("Cloud SQL '%s' must require SSL connections [SC-8]", [resource.name])
}

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_compute_instance"
	sa := resource.change.after.service_account[0]
	contains(sa.email, "compute@developer.gserviceaccount.com")
	msg := sprintf("Instance '%s' uses default service account [AC-6]", [resource.name])
}

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_container_cluster"
	not resource.change.after.workload_identity_config
	msg := sprintf("GKE cluster '%s' must enable Workload Identity [IA-2]", [resource.name])
}
