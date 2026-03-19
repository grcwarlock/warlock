package nist.pl.pl_2

import rego.v1

# PL-2: System Security Plans

deny_no_ssp contains msg if {
	some system in input.normalized_data.planning.systems
	not system.security_plan_exists
	msg := sprintf("PL-2: System '%s' does not have a system security plan (SSP)", [system.system_id])
}

deny_ssp_not_current contains msg if {
	some system in input.normalized_data.planning.systems
	system.security_plan_exists
	not system.security_plan_reviewed_within_365_days
	msg := sprintf("PL-2: System security plan for '%s' has not been reviewed within the last 365 days", [system.system_id])
}

deny_ssp_missing_boundary contains msg if {
	some system in input.normalized_data.planning.systems
	system.security_plan_exists
	not system.ssp_defines_authorization_boundary
	msg := sprintf("PL-2: SSP for system '%s' does not define the authorization boundary", [system.system_id])
}

deny_ssp_missing_controls contains msg if {
	some system in input.normalized_data.planning.systems
	system.security_plan_exists
	not system.ssp_documents_controls
	msg := sprintf("PL-2: SSP for system '%s' does not document implemented security controls", [system.system_id])
}

deny_ssp_not_approved contains msg if {
	some system in input.normalized_data.planning.systems
	system.security_plan_exists
	not system.ssp_approved_by_authorizing_official
	msg := sprintf("PL-2: SSP for system '%s' has not been approved by the authorizing official", [system.system_id])
}

default compliant := false

compliant if {
	count(deny_no_ssp) == 0
	count(deny_ssp_not_current) == 0
	count(deny_ssp_missing_boundary) == 0
	count(deny_ssp_missing_controls) == 0
	count(deny_ssp_not_approved) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_ssp],
		[f | some f in deny_ssp_not_current],
	),
	array.concat(
		array.concat(
			[f | some f in deny_ssp_missing_boundary],
			[f | some f in deny_ssp_missing_controls],
		),
		[f | some f in deny_ssp_not_approved],
	),
)

result := {
	"control_id": "PL-2",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
