package soc2.a1

import rego.v1

# SOC 2 A1: Availability
# SLA definitions, DR planning, backup/recovery, RTO/RPO

deny_no_sla_definitions contains msg if {
	not input.normalized_data.availability.sla_defined
	msg := "A1.1: No SLA definitions — availability commitments to customers not established"
}

deny_no_dr_plan contains msg if {
	not input.normalized_data.availability.disaster_recovery_plan_exists
	msg := "A1.2: No disaster recovery plan — recovery procedures for system disruptions not documented"
}

deny_stale_dr_plan contains msg if {
	input.normalized_data.availability.disaster_recovery_plan_exists
	input.normalized_data.availability.dr_plan_last_tested_days > 365
	msg := sprintf("A1.2: Disaster recovery plan last tested %d days ago — annual DR testing required", [input.normalized_data.availability.dr_plan_last_tested_days])
}

deny_no_backup_configuration contains msg if {
	input.provider == "aws"
	not input.normalized_data.availability.backup_enabled
	msg := "A1.2: No backup configuration — data recovery capability not established"
}

deny_no_rto_rpo contains msg if {
	not input.normalized_data.availability.rto_defined
	not input.normalized_data.availability.rpo_defined
	msg := "A1.2: RTO and RPO not defined — recovery time and data loss tolerances not established"
}

deny_single_region contains msg if {
	input.provider == "aws"
	input.normalized_data.availability.multi_region_deployed == false
	msg := "A1.1: Single-region deployment — no geographic redundancy for availability"
}

deny_no_capacity_planning contains msg if {
	not input.normalized_data.availability.capacity_planning_enabled
	msg := "A1.1: No capacity planning — system resources not monitored for availability thresholds"
}

deny_no_incident_response contains msg if {
	not input.normalized_data.availability.incident_response_plan_exists
	msg := "A1.2: No incident response plan for availability events — outage management procedures not defined"
}

default compliant := false

compliant if {
	count(deny_no_sla_definitions) == 0
	count(deny_no_dr_plan) == 0
	count(deny_stale_dr_plan) == 0
	count(deny_no_backup_configuration) == 0
	count(deny_no_rto_rpo) == 0
	count(deny_single_region) == 0
	count(deny_no_capacity_planning) == 0
	count(deny_no_incident_response) == 0
}

findings := array.concat(
	array.concat(
		array.concat(
			[f | some f in deny_no_sla_definitions],
			[f | some f in deny_no_dr_plan],
		),
		array.concat(
			[f | some f in deny_stale_dr_plan],
			[f | some f in deny_no_backup_configuration],
		),
	),
	array.concat(
		array.concat(
			[f | some f in deny_no_rto_rpo],
			[f | some f in deny_single_region],
		),
		array.concat(
			[f | some f in deny_no_capacity_planning],
			[f | some f in deny_no_incident_response],
		),
	),
)

result := {
	"control_id": "A1",
	"framework": "SOC 2",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
