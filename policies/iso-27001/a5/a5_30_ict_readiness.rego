package iso_27001.a5.a5_30

import rego.v1

# A.5.30: ICT Readiness for Business Continuity
# Validates ICT systems have tested backup and recovery capabilities

deny_no_backup_plans contains msg if {
	count(input.normalized_data.backup.plans) == 0
	msg := "A.5.30: No AWS Backup plans exist for business continuity"
}

deny_no_recent_backups contains msg if {
	some plan in input.normalized_data.backup.plans
	plan.last_backup_days > 7
	msg := sprintf("A.5.30: Backup plan '%s' last backup was %d days ago — exceeds 7-day threshold", [plan.name, plan.last_backup_days])
}

deny_no_cross_region_backup contains msg if {
	some plan in input.normalized_data.backup.plans
	not plan.cross_region_copy_enabled
	msg := sprintf("A.5.30: Backup plan '%s' does not have cross-region copy configured", [plan.name])
}

deny_no_restore_testing contains msg if {
	not input.normalized_data.backup.restore_testing_plan_exists
	msg := "A.5.30: No backup restore testing plan configured — recovery capability unvalidated"
}

deny_no_recovery_points contains msg if {
	input.normalized_data.backup.recovery_point_count == 0
	msg := "A.5.30: No recovery points exist in backup vault"
}

default compliant := false

compliant if {
	count(deny_no_backup_plans) == 0
	count(deny_no_recent_backups) == 0
	count(deny_no_recovery_points) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_backup_plans],
		[f | some f in deny_no_recent_backups],
	),
	array.concat(
		[f | some f in deny_no_cross_region_backup],
		array.concat(
			[f | some f in deny_no_restore_testing],
			[f | some f in deny_no_recovery_points],
		),
	),
)

result := {
	"control_id": "A.5.30",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
