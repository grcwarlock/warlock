package nist.ps.ps_5

import rego.v1

# PS-5: Personnel Transfer

deny_no_transfer_process contains msg if {
	not input.normalized_data.transfer_process
	msg := "PS-5: No personnel transfer and reassignment process established"
}

deny_access_not_reviewed contains msg if {
	some person in input.normalized_data.transferred_personnel
	not person.access_reviewed_on_transfer
	msg := sprintf("PS-5: Access not reviewed during transfer of '%s' to new position", [person.name])
}

deny_access_not_modified contains msg if {
	some person in input.normalized_data.transferred_personnel
	person.access_reviewed_on_transfer
	person.access_modification_needed
	not person.access_modified
	msg := sprintf("PS-5: Access not modified for transferred employee '%s' per new role requirements", [person.name])
}

deny_late_transfer_action contains msg if {
	some person in input.normalized_data.transferred_personnel
	person.days_to_process > 5
	msg := sprintf("PS-5: Transfer processing for '%s' took %d days (exceeds 5-day requirement)", [person.name, person.days_to_process])
}

deny_no_notification contains msg if {
	some person in input.normalized_data.transferred_personnel
	not person.security_notified
	msg := sprintf("PS-5: Security team not notified of transfer for '%s'", [person.name])
}

default compliant := false

compliant if {
	count(deny_no_transfer_process) == 0
	count(deny_access_not_reviewed) == 0
	count(deny_access_not_modified) == 0
	count(deny_late_transfer_action) == 0
	count(deny_no_notification) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_transfer_process],
		[f | some f in deny_access_not_reviewed],
	),
	array.concat(
		[f | some f in deny_access_not_modified],
		array.concat(
			[f | some f in deny_late_transfer_action],
			[f | some f in deny_no_notification],
		),
	),
)

result := {
	"control_id": "PS-5",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
