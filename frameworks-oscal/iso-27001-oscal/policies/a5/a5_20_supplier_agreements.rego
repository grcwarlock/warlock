package iso_27001.a5.a5_20

import rego.v1

# A.5.20: Addressing Information Security Within Supplier Agreements
# Validates supplier agreements include security requirements

deny_no_supplier_agreements contains msg if {
	not input.normalized_data.policies.supplier_agreements_stored
	msg := "A.5.20: No supplier agreements are stored in the document repository"
}

deny_agreements_not_versioned contains msg if {
	some bucket in input.normalized_data.s3.buckets
	bucket.purpose == "agreements"
	not bucket.versioning_enabled
	msg := sprintf("A.5.20: Agreements bucket '%s' does not have versioning enabled", [bucket.name])
}

deny_no_baa_accepted contains msg if {
	input.normalized_data.compliance.handles_phi
	not input.normalized_data.compliance.baa_accepted
	msg := "A.5.20: Business Associate Agreement (BAA) not accepted despite handling PHI"
}

deny_agreements_not_encrypted contains msg if {
	some bucket in input.normalized_data.s3.buckets
	bucket.purpose == "agreements"
	not bucket.encryption_enabled
	msg := sprintf("A.5.20: Agreements bucket '%s' is not encrypted", [bucket.name])
}

default compliant := false

compliant if {
	count(deny_no_supplier_agreements) == 0
	count(deny_agreements_not_versioned) == 0
	count(deny_agreements_not_encrypted) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_supplier_agreements],
		[f | some f in deny_agreements_not_versioned],
	),
	array.concat(
		[f | some f in deny_no_baa_accepted],
		[f | some f in deny_agreements_not_encrypted],
	),
)

result := {
	"control_id": "A.5.20",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
