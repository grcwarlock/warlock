package ucf.hrs.ucf_hrs_1

import rego.v1

# UCF-HRS-1: Personnel Screening
# Validates that background checks are completed for employees

deny_no_background_check contains msg if {
	some record in input.normalized_data.hr_records
	record.status == "active"
	not _has_background_check(record.employee_id)
	msg := sprintf("UCF-HRS-1: Employee '%s' has no completed background check", [record.employee_id])
}

_has_background_check(employee_id) if {
	some check in input.normalized_data.background_checks
	check.employee_id == employee_id
	check.status == "completed"
}

default compliant := false

compliant if {
	count(deny_no_background_check) == 0
	count(input.normalized_data.hr_records) > 0
}

findings := [f | some f in deny_no_background_check]

result := {
	"control_id": "UCF-HRS-1",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
