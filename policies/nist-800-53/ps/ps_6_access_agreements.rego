package nist.ps.ps_6

import rego.v1

# PS-6: Access Agreements

deny_no_access_agreements contains msg if {
	not input.normalized_data.access_agreement_policy
	msg := "PS-6: No access agreement policy established"
}

deny_user_no_agreement contains msg if {
	some user in input.normalized_data.users
	user.requires_access_agreement
	not user.access_agreement_signed
	msg := sprintf("PS-6: User '%s' has not signed required access agreement", [user.username])
}

deny_agreement_expired contains msg if {
	some user in input.normalized_data.users
	user.access_agreement_signed
	user.agreement_expiration_days < 0
	msg := sprintf("PS-6: Access agreement for user '%s' has expired (%d days past expiration)", [user.username, abs(user.agreement_expiration_days)])
}

deny_nda_not_signed contains msg if {
	some user in input.normalized_data.users
	user.requires_nda
	not user.nda_signed
	msg := sprintf("PS-6: User '%s' has not signed required non-disclosure agreement", [user.username])
}

deny_agreement_not_reviewed contains msg if {
	policy := input.normalized_data.access_agreement_policy
	policy.last_review_days > 365
	msg := sprintf("PS-6: Access agreements have not been reviewed and updated in %d days", [policy.last_review_days])
}

default compliant := false

compliant if {
	count(deny_no_access_agreements) == 0
	count(deny_user_no_agreement) == 0
	count(deny_agreement_expired) == 0
	count(deny_nda_not_signed) == 0
	count(deny_agreement_not_reviewed) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_access_agreements],
		[f | some f in deny_user_no_agreement],
	),
	array.concat(
		[f | some f in deny_agreement_expired],
		array.concat(
			[f | some f in deny_nda_not_signed],
			[f | some f in deny_agreement_not_reviewed],
		),
	),
)

result := {
	"control_id": "PS-6",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
