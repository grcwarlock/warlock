package nist.ma.ma_5

import rego.v1

# MA-5: Maintenance Personnel

deny_unauthorized_personnel contains msg if {
	some person in input.normalized_data.maintenance.personnel
	not person.authorized
	msg := sprintf("MA-5: Maintenance personnel '%s' is not authorized to perform maintenance", [person.person_id])
}

deny_no_background_check contains msg if {
	some person in input.normalized_data.maintenance.personnel
	person.authorized
	not person.background_check_completed
	msg := sprintf("MA-5: Authorized maintenance personnel '%s' has not completed a background check", [person.person_id])
}

deny_expired_credentials contains msg if {
	some person in input.normalized_data.maintenance.personnel
	person.authorized
	person.credentials_expired
	msg := sprintf("MA-5: Maintenance personnel '%s' has expired credentials", [person.person_id])
}

deny_unsupervised_external contains msg if {
	some person in input.normalized_data.maintenance.personnel
	person.external
	not person.supervised
	msg := sprintf("MA-5: External maintenance personnel '%s' is operating without required supervision", [person.person_id])
}

deny_no_personnel_list contains msg if {
	not input.normalized_data.maintenance.authorized_personnel_list_defined
	msg := "MA-5: No authorized maintenance personnel list has been defined"
}

default compliant := false

compliant if {
	count(deny_unauthorized_personnel) == 0
	count(deny_no_background_check) == 0
	count(deny_expired_credentials) == 0
	count(deny_unsupervised_external) == 0
	count(deny_no_personnel_list) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_unauthorized_personnel],
		[f | some f in deny_no_background_check],
	),
	array.concat(
		array.concat(
			[f | some f in deny_expired_credentials],
			[f | some f in deny_unsupervised_external],
		),
		[f | some f in deny_no_personnel_list],
	),
)

result := {
	"control_id": "MA-5",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
