package nist.ma.ma_6

import rego.v1

# MA-6: Timely Maintenance

deny_sla_exceeded contains msg if {
	some system in input.normalized_data.maintenance.systems
	system.maintenance_overdue
	msg := sprintf("MA-6: System '%s' has exceeded its maintenance SLA window by %d days", [system.system_id, system.days_overdue])
}

deny_no_spare_parts contains msg if {
	some system in input.normalized_data.maintenance.systems
	system.critical
	not system.spare_parts_available
	msg := sprintf("MA-6: Critical system '%s' does not have spare parts available for timely repair", [system.system_id])
}

deny_no_sla_defined contains msg if {
	some system in input.normalized_data.maintenance.systems
	not system.sla_defined
	msg := sprintf("MA-6: System '%s' does not have a maintenance SLA defined", [system.system_id])
}

deny_no_mean_time_to_repair contains msg if {
	some system in input.normalized_data.maintenance.systems
	system.critical
	not system.mttr_tracked
	msg := sprintf("MA-6: Critical system '%s' does not track mean time to repair (MTTR)", [system.system_id])
}

default compliant := false

compliant if {
	count(deny_sla_exceeded) == 0
	count(deny_no_spare_parts) == 0
	count(deny_no_sla_defined) == 0
	count(deny_no_mean_time_to_repair) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_sla_exceeded],
		[f | some f in deny_no_spare_parts],
	),
	array.concat(
		[f | some f in deny_no_sla_defined],
		[f | some f in deny_no_mean_time_to_repair],
	),
)

result := {
	"control_id": "MA-6",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
