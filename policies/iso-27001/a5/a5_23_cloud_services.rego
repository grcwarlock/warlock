package iso_27001.a5.a5_23

import rego.v1

# A.5.23: Information Security for Use of Cloud Services
# Validates cloud service security controls and governance

deny_no_landing_zone contains msg if {
	not input.normalized_data.controltower.landing_zone_deployed
	msg := "A.5.23: AWS Control Tower landing zone is not deployed for cloud governance"
}

deny_no_security_hub contains msg if {
	not input.normalized_data.security_hub.enabled
	msg := "A.5.23: Security Hub is not enabled for centralized cloud security management"
}

deny_no_guardrail_scps contains msg if {
	not input.normalized_data.organization.guardrail_scps_attached
	msg := "A.5.23: No guardrail SCPs are attached to organizational units"
}

deny_no_org_cloudtrail contains msg if {
	not input.normalized_data.cloudtrail.organization_trail_enabled
	msg := "A.5.23: No organization-level CloudTrail trail exists for cloud service auditing"
}

deny_cloudtrail_not_multiregion contains msg if {
	input.normalized_data.cloudtrail.enabled
	not input.normalized_data.cloudtrail.is_multi_region
	msg := "A.5.23: CloudTrail is not configured as multi-region — cloud services may not be fully audited"
}

default compliant := false

compliant if {
	count(deny_no_security_hub) == 0
	count(deny_no_guardrail_scps) == 0
	count(deny_no_org_cloudtrail) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_landing_zone],
		[f | some f in deny_no_security_hub],
	),
	array.concat(
		[f | some f in deny_no_guardrail_scps],
		array.concat(
			[f | some f in deny_no_org_cloudtrail],
			[f | some f in deny_cloudtrail_not_multiregion],
		),
	),
)

result := {
	"control_id": "A.5.23",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
