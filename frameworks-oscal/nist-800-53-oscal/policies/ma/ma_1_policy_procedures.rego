package nist.ma.ma_1

import rego.v1

# MA-1: System Maintenance Policy and Procedures

deny_no_maintenance_policy contains msg if {
	not input.normalized_data.maintenance.policy_defined
	msg := "MA-1: Organization has not defined a system maintenance policy"
}

deny_policy_not_reviewed contains msg if {
	input.normalized_data.maintenance.policy_defined
	not input.normalized_data.maintenance.policy_reviewed_within_365_days
	msg := "MA-1: System maintenance policy has not been reviewed within the last 365 days"
}

deny_no_procedures contains msg if {
	not input.normalized_data.maintenance.procedures_documented
	msg := "MA-1: System maintenance procedures are not documented"
}

deny_no_designated_official contains msg if {
	not input.normalized_data.maintenance.designated_official
	msg := "MA-1: No designated official assigned for maintenance policy management"
}

default compliant := false

compliant if {
	count(deny_no_maintenance_policy) == 0
	count(deny_policy_not_reviewed) == 0
	count(deny_no_procedures) == 0
	count(deny_no_designated_official) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_maintenance_policy],
		[f | some f in deny_policy_not_reviewed],
	),
	array.concat(
		[f | some f in deny_no_procedures],
		[f | some f in deny_no_designated_official],
	),
)

result := {
	"control_id": "MA-1",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
