package nist.pe.pe_2

import rego.v1

# PE-2: Physical Access Authorizations

deny_no_authorization_list contains msg if {
	some facility in input.normalized_data.physical_security.facilities
	not facility.access_authorization_list_maintained
	msg := sprintf("PE-2: Facility '%s' does not maintain a physical access authorization list", [facility.facility_id])
}

deny_authorization_not_reviewed contains msg if {
	some facility in input.normalized_data.physical_security.facilities
	facility.access_authorization_list_maintained
	not facility.authorization_list_reviewed_within_90_days
	msg := sprintf("PE-2: Physical access authorization list for facility '%s' has not been reviewed within 90 days", [facility.facility_id])
}

deny_unauthorized_individual contains msg if {
	some person in input.normalized_data.physical_security.access_holders
	not person.authorization_documented
	msg := sprintf("PE-2: Individual '%s' has physical access without documented authorization", [person.person_id])
}

deny_no_authorization_credentials contains msg if {
	some person in input.normalized_data.physical_security.access_holders
	person.authorization_documented
	not person.credentials_issued
	msg := sprintf("PE-2: Authorized individual '%s' has not been issued physical access credentials", [person.person_id])
}

default compliant := false

compliant if {
	count(deny_no_authorization_list) == 0
	count(deny_authorization_not_reviewed) == 0
	count(deny_unauthorized_individual) == 0
	count(deny_no_authorization_credentials) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_authorization_list],
		[f | some f in deny_authorization_not_reviewed],
	),
	array.concat(
		[f | some f in deny_unauthorized_individual],
		[f | some f in deny_no_authorization_credentials],
	),
)

result := {
	"control_id": "PE-2",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
