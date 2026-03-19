package nist.cp.cp_9_test

import rego.v1

import data.nist.cp.cp_9

test_compliant_backups if {
	result := cp_9.result with input as {
		"provider": "aws",
		"normalized_data": {
			"backup_configuration": {
				"automated_enabled": true,
				"backup_frequency_hours": 12,
				"retention_days": 30,
				"encryption_enabled": true,
				"last_restore_test_days": 60,
				"monitoring_enabled": true,
			},
			"databases": [
				{"name": "prod-db", "automated_backup_enabled": true},
			],
		},
	}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_backup if {
	result := cp_9.result with input as {
		"provider": "aws",
		"normalized_data": {"databases": []},
	}
	result.compliant == false
}
