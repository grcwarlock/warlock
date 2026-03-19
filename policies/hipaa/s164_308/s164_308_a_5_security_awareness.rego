package hipaa.s164_308.s164_308_a_5

import rego.v1

# 164.308(a)(5): Security Awareness and Training
# Requires a security awareness and training program for all workforce members

deny_no_training_program contains msg if {
	not input.normalized_data.training.program_exists
	msg := "164.308(a)(5): No security awareness training program exists for workforce members"
}

deny_user_not_trained contains msg if {
	some user in input.normalized_data.users
	user.account_enabled
	not user.security_training_completed
	msg := sprintf("164.308(a)(5): User '%s' has not completed security awareness training", [user.username])
}

deny_training_expired contains msg if {
	some user in input.normalized_data.users
	user.account_enabled
	user.security_training_completed
	user.training_completion_days > 365
	msg := sprintf("164.308(a)(5): User '%s' security training is expired — completed %d days ago", [user.username, user.training_completion_days])
}

deny_no_phishing_training contains msg if {
	not input.normalized_data.training.phishing_awareness_included
	msg := "164.308(a)(5): Security training does not include phishing awareness — must address protection from malicious software"
}

default compliant := false

compliant if {
	count(deny_no_training_program) == 0
	count(deny_user_not_trained) == 0
	count(deny_training_expired) == 0
	count(deny_no_phishing_training) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_training_program],
		[f | some f in deny_user_not_trained],
	),
	array.concat(
		[f | some f in deny_training_expired],
		[f | some f in deny_no_phishing_training],
	),
)

result := {
	"control_id": "164.308(a)(5)",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
