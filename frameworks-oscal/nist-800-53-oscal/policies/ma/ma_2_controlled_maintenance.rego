package nist.ma.ma_2

import rego.v1

# MA-2: Controlled Maintenance

deny_unapproved_maintenance contains msg if {
	some activity in input.normalized_data.maintenance.activities
	not activity.approved
	msg := sprintf("MA-2: Maintenance activity '%s' on '%s' was not approved prior to execution", [activity.activity_id, activity.target_system])
}

deny_no_maintenance_schedule contains msg if {
	not input.normalized_data.maintenance.schedule_defined
	msg := "MA-2: No maintenance schedule has been defined for the organization"
}

deny_no_maintenance_records contains msg if {
	some system in input.normalized_data.maintenance.systems
	not system.maintenance_records_kept
	msg := sprintf("MA-2: System '%s' does not maintain maintenance records", [system.system_id])
}

deny_maintenance_not_logged contains msg if {
	some activity in input.normalized_data.maintenance.activities
	activity.approved
	not activity.logged
	msg := sprintf("MA-2: Approved maintenance activity '%s' was not logged upon completion", [activity.activity_id])
}

default compliant := false

compliant if {
	count(deny_unapproved_maintenance) == 0
	count(deny_no_maintenance_schedule) == 0
	count(deny_no_maintenance_records) == 0
	count(deny_maintenance_not_logged) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_unapproved_maintenance],
		[f | some f in deny_no_maintenance_schedule],
	),
	array.concat(
		[f | some f in deny_no_maintenance_records],
		[f | some f in deny_maintenance_not_logged],
	),
)

result := {
	"control_id": "MA-2",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
