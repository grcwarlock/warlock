package nist.ca.ca_6

import rego.v1

# CA-6: Authorization
# Validates system authorization is documented and current

deny_no_authorization contains msg if {
	not input.normalized_data.system_authorization
	msg := "CA-6: No system authorization (ATO) documentation found"
}

deny_no_authorizing_official contains msg if {
	input.normalized_data.system_authorization
	not input.normalized_data.system_authorization.authorizing_official
	msg := "CA-6: No authorizing official designated for the system"
}

deny_authorization_expired contains msg if {
	input.normalized_data.system_authorization
	input.normalized_data.system_authorization.expiry_days <= 0
	msg := "CA-6: System authorization (ATO) has expired"
}

deny_authorization_expiring_soon contains msg if {
	input.normalized_data.system_authorization
	input.normalized_data.system_authorization.expiry_days > 0
	input.normalized_data.system_authorization.expiry_days <= 90
	msg := sprintf("CA-6: System authorization (ATO) expires in %d days", [input.normalized_data.system_authorization.expiry_days])
}

deny_no_authorization_boundary contains msg if {
	input.normalized_data.system_authorization
	not input.normalized_data.system_authorization.boundary_defined
	msg := "CA-6: System authorization boundary is not defined"
}

deny_significant_change_not_reauthorized contains msg if {
	input.normalized_data.system_authorization
	input.normalized_data.system_authorization.significant_change_detected
	not input.normalized_data.system_authorization.reauthorization_initiated
	msg := "CA-6: Significant system change detected but reauthorization has not been initiated"
}

default compliant := false

compliant if {
	count(deny_no_authorization) == 0
	count(deny_no_authorizing_official) == 0
	count(deny_authorization_expired) == 0
	count(deny_no_authorization_boundary) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_authorization],
		[f | some f in deny_no_authorizing_official],
	),
	array.concat(
		[f | some f in deny_authorization_expired],
		array.concat(
			[f | some f in deny_authorization_expiring_soon],
			array.concat(
				[f | some f in deny_no_authorization_boundary],
				[f | some f in deny_significant_change_not_reauthorized],
			),
		),
	),
)

result := {
	"control_id": "CA-6",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
