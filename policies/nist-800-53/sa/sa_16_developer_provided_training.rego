package nist.sa.sa_16

import rego.v1

# SA-16: Developer-Provided Training

deny_no_developer_training contains msg if {
	not input.normalized_data.developer_training
	msg := "SA-16: No developer-provided training on security functions and controls"
}

deny_training_not_current contains msg if {
	dt := input.normalized_data.developer_training
	dt.last_update_days > 365
	msg := sprintf("SA-16: Developer-provided training materials have not been updated in %d days", [dt.last_update_days])
}

deny_training_no_secure_coding contains msg if {
	dt := input.normalized_data.developer_training
	not dt.covers_secure_coding
	msg := "SA-16: Developer training does not cover secure coding practices"
}

deny_developers_not_trained contains msg if {
	some dev in input.normalized_data.developers
	not dev.security_training_completed
	msg := sprintf("SA-16: Developer '%s' has not completed required security training", [dev.name])
}

default compliant := false

compliant if {
	count(deny_no_developer_training) == 0
	count(deny_training_not_current) == 0
	count(deny_training_no_secure_coding) == 0
	count(deny_developers_not_trained) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_developer_training],
		[f | some f in deny_training_not_current],
	),
	array.concat(
		[f | some f in deny_training_no_secure_coding],
		[f | some f in deny_developers_not_trained],
	),
)

result := {
	"control_id": "SA-16",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
