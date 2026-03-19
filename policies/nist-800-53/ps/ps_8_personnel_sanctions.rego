package nist.ps.ps_8

import rego.v1

# PS-8: Personnel Sanctions

deny_no_sanctions_process contains msg if {
	not input.normalized_data.personnel_sanctions
	msg := "PS-8: No formal personnel sanctions process established"
}

deny_sanctions_not_documented contains msg if {
	sanctions := input.normalized_data.personnel_sanctions
	not sanctions.sanctions_documented
	msg := "PS-8: Personnel sanctions are not formally documented"
}

deny_no_due_process contains msg if {
	sanctions := input.normalized_data.personnel_sanctions
	not sanctions.due_process_defined
	msg := "PS-8: Due process procedures for sanctions have not been defined"
}

deny_sanctions_not_communicated contains msg if {
	sanctions := input.normalized_data.personnel_sanctions
	not sanctions.communicated_to_personnel
	msg := "PS-8: Sanctions process has not been communicated to personnel"
}

deny_no_escalation_procedures contains msg if {
	sanctions := input.normalized_data.personnel_sanctions
	not sanctions.escalation_procedures
	msg := "PS-8: No escalation procedures defined for personnel sanctions"
}

default compliant := false

compliant if {
	count(deny_no_sanctions_process) == 0
	count(deny_sanctions_not_documented) == 0
	count(deny_no_due_process) == 0
	count(deny_sanctions_not_communicated) == 0
	count(deny_no_escalation_procedures) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_sanctions_process],
		[f | some f in deny_sanctions_not_documented],
	),
	array.concat(
		[f | some f in deny_no_due_process],
		array.concat(
			[f | some f in deny_sanctions_not_communicated],
			[f | some f in deny_no_escalation_procedures],
		),
	),
)

result := {
	"control_id": "PS-8",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
