package nist.ir.ir_4

import rego.v1

# IR-4: Incident Handling
# Validates incident handling capability including preparation, detection, analysis, containment, eradication, and recovery

deny_no_incident_handling contains msg if {
	not input.normalized_data.incident_handling
	msg := "IR-4: No incident handling capability configured"
}

deny_no_detection_capability contains msg if {
	input.normalized_data.incident_handling
	not input.normalized_data.incident_handling.detection_configured
	msg := "IR-4: Incident detection capability is not configured"
}

deny_no_guardduty contains msg if {
	input.provider == "aws"
	not input.normalized_data.incident_handling.guardduty_enabled
	msg := "IR-4: AWS GuardDuty is not enabled for threat detection"
}

deny_no_sentinel contains msg if {
	input.provider == "azure"
	not input.normalized_data.incident_handling.sentinel_enabled
	msg := "IR-4: Azure Sentinel is not enabled for threat detection and incident handling"
}

deny_no_containment_procedures contains msg if {
	input.normalized_data.incident_handling
	not input.normalized_data.incident_handling.containment_procedures_documented
	msg := "IR-4: Incident containment procedures are not documented"
}

deny_no_eradication_procedures contains msg if {
	input.normalized_data.incident_handling
	not input.normalized_data.incident_handling.eradication_procedures_documented
	msg := "IR-4: Incident eradication procedures are not documented"
}

deny_no_recovery_procedures contains msg if {
	input.normalized_data.incident_handling
	not input.normalized_data.incident_handling.recovery_procedures_documented
	msg := "IR-4: Incident recovery procedures are not documented"
}

deny_no_lessons_learned contains msg if {
	input.normalized_data.incident_handling
	input.normalized_data.incident_handling.incidents_occurred
	not input.normalized_data.incident_handling.lessons_learned_conducted
	msg := "IR-4: Lessons learned activities have not been conducted after incidents"
}

default compliant := false

compliant if {
	count(deny_no_incident_handling) == 0
	count(deny_no_detection_capability) == 0
	count(deny_no_containment_procedures) == 0
	count(deny_no_eradication_procedures) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_incident_handling],
		[f | some f in deny_no_detection_capability],
	),
	array.concat(
		array.concat(
			[f | some f in deny_no_guardduty],
			[f | some f in deny_no_sentinel],
		),
		array.concat(
			[f | some f in deny_no_containment_procedures],
			array.concat(
				[f | some f in deny_no_eradication_procedures],
				array.concat(
					[f | some f in deny_no_recovery_procedures],
					[f | some f in deny_no_lessons_learned],
				),
			),
		),
	),
)

result := {
	"control_id": "IR-4",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
