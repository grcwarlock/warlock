package nist.cp.cp_7

import rego.v1

# CP-7: Alternate Processing Site
# Validates DR site is configured for continuity of operations

deny_no_alternate_processing contains msg if {
	not input.normalized_data.alternate_processing
	msg := "CP-7: No alternate processing site configured for disaster recovery"
}

deny_no_multi_region_deployment contains msg if {
	input.provider == "aws"
	not input.normalized_data.alternate_processing.multi_region_enabled
	msg := "CP-7: AWS multi-region deployment is not configured for alternate processing"
}

deny_no_multi_region_deployment contains msg if {
	input.provider == "azure"
	not input.normalized_data.alternate_processing.paired_region_enabled
	msg := "CP-7: Azure paired region deployment is not configured for alternate processing"
}

deny_no_multi_region_deployment contains msg if {
	input.provider == "gcp"
	not input.normalized_data.alternate_processing.multi_region_enabled
	msg := "CP-7: GCP multi-region deployment is not configured for alternate processing"
}

deny_no_failover_capability contains msg if {
	input.normalized_data.alternate_processing
	not input.normalized_data.alternate_processing.failover_configured
	msg := "CP-7: Automated failover to alternate processing site is not configured"
}

deny_rto_not_met contains msg if {
	input.normalized_data.alternate_processing
	input.normalized_data.alternate_processing.estimated_rto_hours > input.normalized_data.alternate_processing.required_rto_hours
	msg := sprintf("CP-7: Estimated RTO (%d hours) exceeds required RTO (%d hours)", [input.normalized_data.alternate_processing.estimated_rto_hours, input.normalized_data.alternate_processing.required_rto_hours])
}

deny_no_transfer_agreement contains msg if {
	input.normalized_data.alternate_processing
	not input.normalized_data.alternate_processing.transfer_agreement_documented
	msg := "CP-7: Operations transfer agreement for alternate processing site is not documented"
}

deny_site_not_tested contains msg if {
	input.normalized_data.alternate_processing
	input.normalized_data.alternate_processing.last_failover_test_days > 365
	msg := sprintf("CP-7: Alternate processing site failover has not been tested in %d days", [input.normalized_data.alternate_processing.last_failover_test_days])
}

default compliant := false

compliant if {
	count(deny_no_alternate_processing) == 0
	count(deny_no_multi_region_deployment) == 0
	count(deny_no_failover_capability) == 0
	count(deny_rto_not_met) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_alternate_processing],
		[f | some f in deny_no_multi_region_deployment],
	),
	array.concat(
		[f | some f in deny_no_failover_capability],
		array.concat(
			[f | some f in deny_rto_not_met],
			array.concat(
				[f | some f in deny_no_transfer_agreement],
				[f | some f in deny_site_not_tested],
			),
		),
	),
)

result := {
	"control_id": "CP-7",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
