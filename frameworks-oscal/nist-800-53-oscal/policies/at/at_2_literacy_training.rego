package nist.at.at_2

import rego.v1

# AT-2: Literacy Training and Awareness
# Validates security awareness training is provided to all system users

deny_no_training_program contains msg if {
	not input.normalized_data.security_training
	msg := "AT-2: No security awareness training program configured"
}

deny_training_not_completed contains msg if {
	some user in input.normalized_data.users
	not user.security_training_completed
	msg := sprintf("AT-2: User '%s' has not completed security awareness training", [user.username])
}

deny_training_expired contains msg if {
	some user in input.normalized_data.users
	user.security_training_completed
	user.training_completion_days > 365
	msg := sprintf("AT-2: User '%s' security awareness training expired (%d days since completion)", [user.username, user.training_completion_days])
}

deny_no_phishing_awareness contains msg if {
	input.normalized_data.security_training
	not input.normalized_data.security_training.phishing_module_included
	msg := "AT-2: Security awareness training does not include phishing awareness module"
}

deny_no_social_engineering_module contains msg if {
	input.normalized_data.security_training
	not input.normalized_data.security_training.social_engineering_module_included
	msg := "AT-2: Security awareness training does not include social engineering awareness"
}

deny_no_insider_threat_module contains msg if {
	input.normalized_data.security_training
	not input.normalized_data.security_training.insider_threat_module_included
	msg := "AT-2: Security awareness training does not include insider threat awareness"
}

deny_new_hire_training_gap contains msg if {
	some user in input.normalized_data.users
	user.account_age_days <= 30
	not user.security_training_completed
	msg := sprintf("AT-2: New user '%s' (account age %d days) has not completed initial security training", [user.username, user.account_age_days])
}

default compliant := false

compliant if {
	count(deny_no_training_program) == 0
	count(deny_training_not_completed) == 0
	count(deny_training_expired) == 0
	count(deny_no_phishing_awareness) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_training_program],
		[f | some f in deny_training_not_completed],
	),
	array.concat(
		[f | some f in deny_training_expired],
		array.concat(
			[f | some f in deny_no_phishing_awareness],
			array.concat(
				[f | some f in deny_no_social_engineering_module],
				array.concat(
					[f | some f in deny_no_insider_threat_module],
					[f | some f in deny_new_hire_training_gap],
				),
			),
		),
	),
)

result := {
	"control_id": "AT-2",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
