package nist.ca.ca_3

import rego.v1

# CA-3: Information Exchange
# Validates secure information exchange between systems

deny_no_interconnection_agreements contains msg if {
	not input.normalized_data.system_interconnections
	msg := "CA-3: No system interconnection agreements documented"
}

deny_unauthorized_connections contains msg if {
	some conn in input.normalized_data.system_interconnections
	not conn.authorized
	msg := sprintf("CA-3: System interconnection '%s' to '%s' is not authorized", [conn.source_system, conn.target_system])
}

deny_agreement_expired contains msg if {
	some conn in input.normalized_data.system_interconnections
	conn.authorized
	conn.agreement_expiry_days <= 0
	msg := sprintf("CA-3: Interconnection agreement for '%s' to '%s' has expired", [conn.source_system, conn.target_system])
}

deny_no_security_requirements contains msg if {
	some conn in input.normalized_data.system_interconnections
	conn.authorized
	not conn.security_requirements_documented
	msg := sprintf("CA-3: Security requirements not documented for interconnection '%s' to '%s'", [conn.source_system, conn.target_system])
}

deny_no_encryption_in_transit contains msg if {
	some conn in input.normalized_data.system_interconnections
	conn.authorized
	not conn.encrypted
	msg := sprintf("CA-3: Data exchange between '%s' and '%s' is not encrypted in transit", [conn.source_system, conn.target_system])
}

deny_agreement_not_reviewed contains msg if {
	some conn in input.normalized_data.system_interconnections
	conn.authorized
	conn.last_review_days > 365
	msg := sprintf("CA-3: Interconnection agreement for '%s' to '%s' has not been reviewed in %d days", [conn.source_system, conn.target_system, conn.last_review_days])
}

default compliant := false

compliant if {
	count(deny_no_interconnection_agreements) == 0
	count(deny_unauthorized_connections) == 0
	count(deny_agreement_expired) == 0
	count(deny_no_encryption_in_transit) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_interconnection_agreements],
		[f | some f in deny_unauthorized_connections],
	),
	array.concat(
		[f | some f in deny_agreement_expired],
		array.concat(
			[f | some f in deny_no_security_requirements],
			array.concat(
				[f | some f in deny_no_encryption_in_transit],
				[f | some f in deny_agreement_not_reviewed],
			),
		),
	),
)

result := {
	"control_id": "CA-3",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
