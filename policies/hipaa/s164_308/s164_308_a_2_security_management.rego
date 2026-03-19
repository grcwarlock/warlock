package hipaa.s164_308.s164_308_a_2

import rego.v1

# 164.308(a)(2): Assigned Security Responsibility
# Requires identification of a security official responsible for
# developing and implementing security policies and procedures

deny_no_security_officer contains msg if {
	not input.normalized_data.organization.security_officer_assigned
	msg := "164.308(a)(2): No security officer has been designated — a specific individual must be assigned responsibility for ePHI security"
}

deny_no_security_officer_contact contains msg if {
	input.normalized_data.organization.security_officer_assigned
	not input.normalized_data.organization.security_officer_contact_documented
	msg := "164.308(a)(2): Security officer contact information is not documented and accessible to workforce"
}

deny_no_security_responsibilities_defined contains msg if {
	input.normalized_data.organization.security_officer_assigned
	not input.normalized_data.organization.security_responsibilities_documented
	msg := "164.308(a)(2): Security officer responsibilities are not formally documented"
}

default compliant := false

compliant if {
	count(deny_no_security_officer) == 0
	count(deny_no_security_officer_contact) == 0
	count(deny_no_security_responsibilities_defined) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_security_officer],
		[f | some f in deny_no_security_officer_contact],
	),
	[f | some f in deny_no_security_responsibilities_defined],
)

result := {
	"control_id": "164.308(a)(2)",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
