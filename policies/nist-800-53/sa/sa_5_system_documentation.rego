package nist.sa.sa_5

import rego.v1

# SA-5: System Documentation

deny_no_admin_documentation contains msg if {
	not input.normalized_data.system_documentation
	msg := "SA-5: No administrator documentation for the information system"
}

deny_no_user_documentation contains msg if {
	doc := input.normalized_data.system_documentation
	not doc.user_guide_available
	msg := "SA-5: No user documentation available for the information system"
}

deny_documentation_outdated contains msg if {
	doc := input.normalized_data.system_documentation
	doc.last_update_days > 365
	msg := sprintf("SA-5: System documentation has not been updated in %d days", [doc.last_update_days])
}

deny_no_security_configuration_docs contains msg if {
	doc := input.normalized_data.system_documentation
	not doc.security_configuration_documented
	msg := "SA-5: Security configuration of the system is not documented"
}

deny_no_architecture_docs contains msg if {
	doc := input.normalized_data.system_documentation
	not doc.architecture_documented
	msg := "SA-5: System security architecture is not documented"
}

default compliant := false

compliant if {
	count(deny_no_admin_documentation) == 0
	count(deny_no_user_documentation) == 0
	count(deny_documentation_outdated) == 0
	count(deny_no_security_configuration_docs) == 0
	count(deny_no_architecture_docs) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_admin_documentation],
		[f | some f in deny_no_user_documentation],
	),
	array.concat(
		[f | some f in deny_documentation_outdated],
		array.concat(
			[f | some f in deny_no_security_configuration_docs],
			[f | some f in deny_no_architecture_docs],
		),
	),
)

result := {
	"control_id": "SA-5",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
