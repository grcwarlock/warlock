package nist.cp.cp_9

import rego.v1

# CP-9: System Backup
# Validates automated backups are configured for system and user data

deny_no_backup_config contains msg if {
	not input.normalized_data.backup_configuration
	msg := "CP-9: No backup configuration found"
}

deny_no_automated_backups contains msg if {
	input.normalized_data.backup_configuration
	not input.normalized_data.backup_configuration.automated_enabled
	msg := "CP-9: Automated backups are not enabled"
}

deny_backup_frequency_insufficient contains msg if {
	input.normalized_data.backup_configuration
	input.normalized_data.backup_configuration.backup_frequency_hours > 24
	msg := sprintf("CP-9: Backup frequency (%d hours) exceeds maximum interval of 24 hours", [input.normalized_data.backup_configuration.backup_frequency_hours])
}

deny_no_rds_backup contains msg if {
	input.provider == "aws"
	some db in input.normalized_data.databases
	not db.automated_backup_enabled
	msg := sprintf("CP-9: RDS instance '%s' does not have automated backups enabled", [db.name])
}

deny_insufficient_retention contains msg if {
	input.normalized_data.backup_configuration
	input.normalized_data.backup_configuration.retention_days < 30
	msg := sprintf("CP-9: Backup retention period (%d days) is less than 30-day minimum", [input.normalized_data.backup_configuration.retention_days])
}

deny_backups_not_encrypted contains msg if {
	input.normalized_data.backup_configuration
	not input.normalized_data.backup_configuration.encryption_enabled
	msg := "CP-9: Backups are not encrypted at rest"
}

deny_no_backup_testing contains msg if {
	input.normalized_data.backup_configuration
	input.normalized_data.backup_configuration.last_restore_test_days > 90
	msg := sprintf("CP-9: Backup restore has not been tested in %d days (exceeds 90-day requirement)", [input.normalized_data.backup_configuration.last_restore_test_days])
}

deny_no_backup_monitoring contains msg if {
	input.normalized_data.backup_configuration
	not input.normalized_data.backup_configuration.monitoring_enabled
	msg := "CP-9: Backup job monitoring and alerting is not configured"
}

default compliant := false

compliant if {
	count(deny_no_backup_config) == 0
	count(deny_no_automated_backups) == 0
	count(deny_backup_frequency_insufficient) == 0
	count(deny_no_rds_backup) == 0
	count(deny_backups_not_encrypted) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_backup_config],
		[f | some f in deny_no_automated_backups],
	),
	array.concat(
		[f | some f in deny_backup_frequency_insufficient],
		array.concat(
			[f | some f in deny_no_rds_backup],
			array.concat(
				[f | some f in deny_insufficient_retention],
				array.concat(
					[f | some f in deny_backups_not_encrypted],
					array.concat(
						[f | some f in deny_no_backup_testing],
						[f | some f in deny_no_backup_monitoring],
					),
				),
			),
		),
	),
)

result := {
	"control_id": "CP-9",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
