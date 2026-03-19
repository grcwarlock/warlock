package iso_27001.a8.a8_13

import rego.v1

# A.8.13: Information Backup
# Validates backup policies and regular backup testing

deny_no_backup_plans contains msg if {
	count(input.normalized_data.backup.plans) == 0
	msg := "A.8.13: No AWS Backup plans configured"
}

deny_no_recent_recovery_points contains msg if {
	input.normalized_data.backup.recovery_point_count == 0
	msg := "A.8.13: No recovery points exist — backups may not be running"
}

deny_no_restore_testing contains msg if {
	not input.normalized_data.backup.restore_testing_plan_exists
	msg := "A.8.13: No restore testing plan configured — backup reliability unvalidated"
}

deny_backup_plan_no_lifecycle contains msg if {
	some plan in input.normalized_data.backup.plans
	not plan.lifecycle_configured
	msg := sprintf("A.8.13: Backup plan '%s' has no lifecycle/retention configuration", [plan.name])
}

deny_stale_backups contains msg if {
	some plan in input.normalized_data.backup.plans
	plan.last_backup_days > 2
	msg := sprintf("A.8.13: Backup plan '%s' last backup was %d days ago", [plan.name, plan.last_backup_days])
}

default compliant := false

compliant if {
	count(deny_no_backup_plans) == 0
	count(deny_no_recent_recovery_points) == 0
	count(deny_stale_backups) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_backup_plans],
		[f | some f in deny_no_recent_recovery_points],
	),
	array.concat(
		[f | some f in deny_no_restore_testing],
		array.concat(
			[f | some f in deny_backup_plan_no_lifecycle],
			[f | some f in deny_stale_backups],
		),
	),
)

result := {
	"control_id": "A.8.13",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
