package nist.ps.ps_4

import rego.v1

# PS-4: Personnel Termination

deny_no_termination_process contains msg if {
	not input.normalized_data.termination_process
	msg := "PS-4: No personnel termination process established"
}

deny_access_not_revoked contains msg if {
	some person in input.normalized_data.terminated_personnel
	not person.access_revoked
	msg := sprintf("PS-4: Terminated employee '%s' still has active system access", [person.name])
}

deny_credentials_not_revoked contains msg if {
	some person in input.normalized_data.terminated_personnel
	not person.credentials_revoked
	msg := sprintf("PS-4: Terminated employee '%s' still has active credentials", [person.name])
}

deny_exit_interview_missing contains msg if {
	some person in input.normalized_data.terminated_personnel
	not person.exit_interview_completed
	msg := sprintf("PS-4: No exit interview conducted for terminated employee '%s'", [person.name])
}

deny_property_not_returned contains msg if {
	some person in input.normalized_data.terminated_personnel
	not person.property_returned
	msg := sprintf("PS-4: Organization property not returned by terminated employee '%s'", [person.name])
}

deny_late_access_revocation contains msg if {
	some person in input.normalized_data.terminated_personnel
	person.access_revoked
	person.hours_to_revoke > 24
	msg := sprintf("PS-4: Access revocation for '%s' took %d hours (exceeds 24-hour requirement)", [person.name, person.hours_to_revoke])
}

default compliant := false

compliant if {
	count(deny_no_termination_process) == 0
	count(deny_access_not_revoked) == 0
	count(deny_credentials_not_revoked) == 0
	count(deny_exit_interview_missing) == 0
	count(deny_property_not_returned) == 0
	count(deny_late_access_revocation) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_termination_process],
		[f | some f in deny_access_not_revoked],
	),
	array.concat(
		array.concat(
			[f | some f in deny_credentials_not_revoked],
			[f | some f in deny_exit_interview_missing],
		),
		array.concat(
			[f | some f in deny_property_not_returned],
			[f | some f in deny_late_access_revocation],
		),
	),
)

result := {
	"control_id": "PS-4",
	"compliant": compliant,
	"findings": findings,
	"severity": "critical",
}
