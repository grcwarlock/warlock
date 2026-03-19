package cmmc.ma.ma_l2_3_7_1

import rego.v1

# MA.L2-3.7.1: System Maintenance
# Perform maintenance on organizational systems

deny_no_maintenance_schedule contains msg if {
	some system in input.normalized_data.systems
	not system.maintenance_schedule_documented
	msg := sprintf("MA.L2-3.7.1: System '%s' does not have a documented maintenance schedule", [system.name])
}

deny_overdue_maintenance contains msg if {
	some system in input.normalized_data.systems
	system.maintenance_schedule_documented
	system.days_since_last_maintenance > 90
	msg := sprintf("MA.L2-3.7.1: System '%s' is %d days overdue for scheduled maintenance", [system.name, system.days_since_last_maintenance])
}

deny_no_maintenance_logging contains msg if {
	some system in input.normalized_data.systems
	not system.maintenance_activities_logged
	msg := sprintf("MA.L2-3.7.1: System '%s' does not log maintenance activities — all maintenance must be documented", [system.name])
}

default compliant := false

compliant if {
	count(deny_no_maintenance_schedule) == 0
	count(deny_overdue_maintenance) == 0
	count(deny_no_maintenance_logging) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_maintenance_schedule],
		[f | some f in deny_overdue_maintenance],
	),
	[f | some f in deny_no_maintenance_logging],
)

result := {
	"control_id": "MA.L2-3.7.1",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
