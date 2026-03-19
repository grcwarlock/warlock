package nist.sr.sr_9

import rego.v1

# SR-9: Tamper Resistance and Detection

deny_no_tamper_protection contains msg if {
	not input.normalized_data.tamper_protection
	msg := "SR-9: No tamper resistance and detection measures implemented"
}

deny_no_tamper_evident_packaging contains msg if {
	tp := input.normalized_data.tamper_protection
	not tp.tamper_evident_packaging
	msg := "SR-9: No tamper-evident packaging used for critical component delivery"
}

deny_no_tamper_detection contains msg if {
	tp := input.normalized_data.tamper_protection
	not tp.tamper_detection_mechanisms
	msg := "SR-9: No tamper detection mechanisms deployed for critical systems"
}

deny_no_inspection_procedures contains msg if {
	tp := input.normalized_data.tamper_protection
	not tp.inspection_procedures_defined
	msg := "SR-9: No inspection procedures defined for detecting tampering"
}

default compliant := false

compliant if {
	count(deny_no_tamper_protection) == 0
	count(deny_no_tamper_evident_packaging) == 0
	count(deny_no_tamper_detection) == 0
	count(deny_no_inspection_procedures) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_tamper_protection],
		[f | some f in deny_no_tamper_evident_packaging],
	),
	array.concat(
		[f | some f in deny_no_tamper_detection],
		[f | some f in deny_no_inspection_procedures],
	),
)

result := {
	"control_id": "SR-9",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
