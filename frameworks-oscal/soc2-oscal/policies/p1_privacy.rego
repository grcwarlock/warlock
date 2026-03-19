package soc2.p1

import rego.v1

# SOC 2 P1: Privacy
# Notice, choice, collection, use, access, disclosure, quality, monitoring

deny_no_privacy_policy contains msg if {
	not input.normalized_data.privacy.privacy_policy_published
	msg := "P1.1: No privacy policy published — notice to data subjects about collection, use, and disclosure not provided"
}

deny_no_consent_mechanisms contains msg if {
	not input.normalized_data.privacy.consent_mechanisms_implemented
	msg := "P1.2: No consent mechanisms — individuals not provided choice regarding collection and use of personal information"
}

deny_no_data_inventory contains msg if {
	not input.normalized_data.privacy.personal_data_inventory_exists
	msg := "P1.3: No personal data inventory — types and sources of personal information collected not documented"
}

deny_no_purpose_limitation contains msg if {
	not input.normalized_data.privacy.purpose_limitation_enforced
	msg := "P1.4: No purpose limitation controls — personal information may be used beyond disclosed purposes"
}

deny_no_dsar_process contains msg if {
	not input.normalized_data.privacy.dsar_process_exists
	msg := "P1.5: No DSAR process — data subject access requests cannot be fulfilled within required timeframes"
}

deny_no_disclosure_controls contains msg if {
	not input.normalized_data.privacy.disclosure_controls_exist
	msg := "P1.6: No disclosure controls — third-party sharing of personal information not governed"
}

deny_no_data_quality_procedures contains msg if {
	not input.normalized_data.privacy.data_quality_procedures_exist
	msg := "P1.7: No data quality procedures — accuracy and completeness of personal information not maintained"
}

deny_no_privacy_monitoring contains msg if {
	not input.normalized_data.privacy.privacy_monitoring_enabled
	msg := "P1.8: No privacy monitoring — compliance with privacy commitments not continuously evaluated"
}

deny_no_privacy_impact_assessment contains msg if {
	not input.normalized_data.privacy.privacy_impact_assessments_performed
	msg := "P1.1: No privacy impact assessments performed — privacy risks of new systems and processes not evaluated"
}

default compliant := false

compliant if {
	count(deny_no_privacy_policy) == 0
	count(deny_no_consent_mechanisms) == 0
	count(deny_no_data_inventory) == 0
	count(deny_no_purpose_limitation) == 0
	count(deny_no_dsar_process) == 0
	count(deny_no_disclosure_controls) == 0
	count(deny_no_data_quality_procedures) == 0
	count(deny_no_privacy_monitoring) == 0
	count(deny_no_privacy_impact_assessment) == 0
}

findings := array.concat(
	array.concat(
		array.concat(
			[f | some f in deny_no_privacy_policy],
			[f | some f in deny_no_consent_mechanisms],
		),
		array.concat(
			[f | some f in deny_no_data_inventory],
			[f | some f in deny_no_purpose_limitation],
		),
	),
	array.concat(
		array.concat(
			[f | some f in deny_no_dsar_process],
			[f | some f in deny_no_disclosure_controls],
		),
		array.concat(
			[f | some f in deny_no_data_quality_procedures],
			array.concat(
				[f | some f in deny_no_privacy_monitoring],
				[f | some f in deny_no_privacy_impact_assessment],
			),
		),
	),
)

result := {
	"control_id": "P1",
	"framework": "SOC 2",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
