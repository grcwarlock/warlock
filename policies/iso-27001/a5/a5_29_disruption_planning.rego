package iso_27001.a5.a5_29

import rego.v1

# A.5.29: Information Security During Disruption
# Validates security controls remain active during business continuity events

deny_cloudtrail_not_multiregion contains msg if {
	input.normalized_data.cloudtrail.enabled
	not input.normalized_data.cloudtrail.is_multi_region
	msg := "A.5.29: CloudTrail is not multi-region — security monitoring may fail during regional disruption"
}

deny_guardduty_not_all_regions contains msg if {
	input.normalized_data.guardduty.enabled
	not input.normalized_data.guardduty.enabled_all_regions
	msg := "A.5.29: GuardDuty is not enabled in all regions — threat detection gaps during disruption"
}

deny_no_config_replication contains msg if {
	not input.normalized_data.s3.security_config_replicated
	msg := "A.5.29: Security configurations are not replicated to DR region"
}

deny_no_bcp_documented contains msg if {
	not input.normalized_data.policies.business_continuity_plan_documented
	msg := "A.5.29: No business continuity plan documented for maintaining security during disruption"
}

default compliant := false

compliant if {
	count(deny_cloudtrail_not_multiregion) == 0
	count(deny_guardduty_not_all_regions) == 0
	count(deny_no_bcp_documented) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_cloudtrail_not_multiregion],
		[f | some f in deny_guardduty_not_all_regions],
	),
	array.concat(
		[f | some f in deny_no_config_replication],
		[f | some f in deny_no_bcp_documented],
	),
)

result := {
	"control_id": "A.5.29",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
