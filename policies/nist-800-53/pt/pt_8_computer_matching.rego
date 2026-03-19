package nist.pt.pt_8

import rego.v1

# PT-8: Computer Matching Requirements

deny_no_matching_policy contains msg if {
	not input.normalized_data.computer_matching
	msg := "PT-8: No computer matching policy established"
}

deny_no_matching_agreements contains msg if {
	cm := input.normalized_data.computer_matching
	not cm.matching_agreements_established
	msg := "PT-8: No computer matching agreements established as required by the Computer Matching and Privacy Protection Act"
}

deny_agreement_not_approved contains msg if {
	some agreement in input.normalized_data.computer_matching.agreements
	not agreement.approved_by_data_integrity_board
	msg := sprintf("PT-8: Computer matching agreement '%s' not approved by Data Integrity Board", [agreement.name])
}

deny_agreement_expired contains msg if {
	some agreement in input.normalized_data.computer_matching.agreements
	agreement.expiration_days < 0
	msg := sprintf("PT-8: Computer matching agreement '%s' has expired (%d days past expiration)", [agreement.name, abs(agreement.expiration_days)])
}

deny_no_due_process contains msg if {
	cm := input.normalized_data.computer_matching
	not cm.due_process_protections
	msg := "PT-8: Due process protections not implemented for individuals affected by computer matching"
}

deny_no_verification_before_action contains msg if {
	cm := input.normalized_data.computer_matching
	not cm.independent_verification
	msg := "PT-8: No independent verification required before adverse action based on matching results"
}

default compliant := false

compliant if {
	count(deny_no_matching_policy) == 0
	count(deny_no_matching_agreements) == 0
	count(deny_agreement_not_approved) == 0
	count(deny_agreement_expired) == 0
	count(deny_no_due_process) == 0
	count(deny_no_verification_before_action) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_matching_policy],
		[f | some f in deny_no_matching_agreements],
	),
	array.concat(
		array.concat(
			[f | some f in deny_agreement_not_approved],
			[f | some f in deny_agreement_expired],
		),
		array.concat(
			[f | some f in deny_no_due_process],
			[f | some f in deny_no_verification_before_action],
		),
	),
)

result := {
	"control_id": "PT-8",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
