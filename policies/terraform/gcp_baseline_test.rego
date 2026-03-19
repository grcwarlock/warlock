package terraform.gcp_test

import rego.v1

import data.terraform.gcp

test_compliant_gcs_uniform_access if {
	count(gcp.deny) == 0 with input as {"resource_changes": [{
		"type": "google_storage_bucket",
		"name": "good-bucket",
		"change": {"after": {"uniform_bucket_level_access": true}},
	}]}
}

test_noncompliant_gcs_no_uniform if {
	count(gcp.deny) > 0 with input as {"resource_changes": [{
		"type": "google_storage_bucket",
		"name": "bad-bucket",
		"change": {"after": {}},
	}]}
}

test_noncompliant_firewall_ssh_open if {
	count(gcp.deny) > 0 with input as {"resource_changes": [{
		"type": "google_compute_firewall",
		"name": "bad-fw",
		"change": {"after": {"direction": "INGRESS", "source_ranges": ["0.0.0.0/0"], "allow": [{"ports": ["22"]}]}},
	}]}
}
