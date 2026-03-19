package iso_27001.a5.a5_32

import rego.v1

# A.5.32: Intellectual Property Rights
# Validates intellectual property protection controls

deny_no_macie contains msg if {
	not input.normalized_data.macie.enabled
	msg := "A.5.32: Macie is not enabled for detecting exposed intellectual property"
}

deny_no_custom_data_identifiers contains msg if {
	input.normalized_data.macie.enabled
	count(input.normalized_data.macie.custom_data_identifiers) == 0
	msg := "A.5.32: No custom Macie data identifiers for proprietary content detection"
}

deny_no_license_tracking contains msg if {
	not input.normalized_data.license_manager.tracking_active
	msg := "A.5.32: License Manager is not configured — software license compliance not tracked"
}

deny_code_repos_public contains msg if {
	some repo in input.normalized_data.codecommit.repositories
	repo.is_public
	msg := sprintf("A.5.32: Code repository '%s' is publicly accessible — IP exposure risk", [repo.name])
}

default compliant := false

compliant if {
	count(deny_no_macie) == 0
	count(deny_no_license_tracking) == 0
	count(deny_code_repos_public) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_macie],
		[f | some f in deny_no_custom_data_identifiers],
	),
	array.concat(
		[f | some f in deny_no_license_tracking],
		[f | some f in deny_code_repos_public],
	),
)

result := {
	"control_id": "A.5.32",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
