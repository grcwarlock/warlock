package nist.pt.pt_6

import rego.v1

# PT-6: System of Records Notice

deny_no_sorn contains msg if {
	not input.normalized_data.system_of_records_notices
	msg := "PT-6: No system of records notices (SORNs) published"
}

deny_system_no_sorn contains msg if {
	some system in input.normalized_data.systems_processing_pii
	system.is_system_of_records
	not system.sorn_published
	msg := sprintf("PT-6: System of records '%s' does not have a published SORN", [system.name])
}

deny_sorn_outdated contains msg if {
	some sorn in input.normalized_data.system_of_records_notices.notices
	sorn.last_review_days > 730
	msg := sprintf("PT-6: SORN for '%s' has not been reviewed in %d days (exceeds 2-year requirement)", [sorn.system_name, sorn.last_review_days])
}

deny_sorn_incomplete contains msg if {
	some sorn in input.normalized_data.system_of_records_notices.notices
	not sorn.includes_routine_uses
	msg := sprintf("PT-6: SORN for '%s' does not include routine uses", [sorn.system_name])
}

deny_sorn_not_published_fr contains msg if {
	some sorn in input.normalized_data.system_of_records_notices.notices
	not sorn.published_in_federal_register
	msg := sprintf("PT-6: SORN for '%s' has not been published in the Federal Register", [sorn.system_name])
}

default compliant := false

compliant if {
	count(deny_no_sorn) == 0
	count(deny_system_no_sorn) == 0
	count(deny_sorn_outdated) == 0
	count(deny_sorn_incomplete) == 0
	count(deny_sorn_not_published_fr) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_sorn],
		[f | some f in deny_system_no_sorn],
	),
	array.concat(
		[f | some f in deny_sorn_outdated],
		array.concat(
			[f | some f in deny_sorn_incomplete],
			[f | some f in deny_sorn_not_published_fr],
		),
	),
)

result := {
	"control_id": "PT-6",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
