package nist.ra.ra_2

import rego.v1

# RA-2: Security Categorization

deny_no_categorization contains msg if {
	not input.normalized_data.security_categorization
	msg := "RA-2: No security categorization performed for the information system"
}

deny_categorization_not_approved contains msg if {
	cat := input.normalized_data.security_categorization
	not cat.approved_by_authorizing_official
	msg := "RA-2: Security categorization has not been approved by the authorizing official"
}

deny_no_fips_199 contains msg if {
	cat := input.normalized_data.security_categorization
	not cat.fips_199_applied
	msg := "RA-2: Security categorization does not apply FIPS 199 guidelines"
}

deny_categorization_outdated contains msg if {
	cat := input.normalized_data.security_categorization
	cat.last_review_days > 365
	msg := sprintf("RA-2: Security categorization has not been reviewed in %d days", [cat.last_review_days])
}

deny_system_no_categorization contains msg if {
	some system in input.normalized_data.system_inventory.systems
	not system.security_categorization
	msg := sprintf("RA-2: System '%s' does not have a security categorization", [system.name])
}

deny_no_impact_levels contains msg if {
	cat := input.normalized_data.security_categorization
	not cat.impact_levels_defined
	msg := "RA-2: Confidentiality, integrity, and availability impact levels not defined"
}

default compliant := false

compliant if {
	count(deny_no_categorization) == 0
	count(deny_categorization_not_approved) == 0
	count(deny_no_fips_199) == 0
	count(deny_categorization_outdated) == 0
	count(deny_system_no_categorization) == 0
	count(deny_no_impact_levels) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_categorization],
		[f | some f in deny_categorization_not_approved],
	),
	array.concat(
		array.concat(
			[f | some f in deny_no_fips_199],
			[f | some f in deny_categorization_outdated],
		),
		array.concat(
			[f | some f in deny_system_no_categorization],
			[f | some f in deny_no_impact_levels],
		),
	),
)

result := {
	"control_id": "RA-2",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
