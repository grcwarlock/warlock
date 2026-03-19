package nist.pm.pm_2

import rego.v1

# PM-2: Information Security Program Leadership Role

deny_no_saop contains msg if {
	not input.normalized_data.senior_agency_official
	msg := "PM-2: No senior agency official for privacy (SAOP) designated"
}

deny_no_ciso contains msg if {
	not input.normalized_data.chief_information_security_officer
	msg := "PM-2: No chief information security officer (CISO) designated"
}

deny_ciso_no_authority contains msg if {
	ciso := input.normalized_data.chief_information_security_officer
	not ciso.has_authority_documented
	msg := "PM-2: CISO authority and responsibilities are not formally documented"
}

deny_ciso_no_direct_report contains msg if {
	ciso := input.normalized_data.chief_information_security_officer
	not ciso.reports_to_head_of_agency
	msg := "PM-2: CISO does not have a direct reporting line to agency head or designated authority"
}

deny_no_security_team contains msg if {
	not input.normalized_data.security_team
	msg := "PM-2: No dedicated information security team established"
}

default compliant := false

compliant if {
	count(deny_no_saop) == 0
	count(deny_no_ciso) == 0
	count(deny_ciso_no_authority) == 0
	count(deny_ciso_no_direct_report) == 0
	count(deny_no_security_team) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_saop],
		[f | some f in deny_no_ciso],
	),
	array.concat(
		[f | some f in deny_ciso_no_authority],
		array.concat(
			[f | some f in deny_ciso_no_direct_report],
			[f | some f in deny_no_security_team],
		),
	),
)

result := {
	"control_id": "PM-2",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
