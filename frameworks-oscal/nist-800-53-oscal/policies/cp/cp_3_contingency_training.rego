package nist.cp.cp_3

import rego.v1

# CP-3: Contingency Training
# Validates training on contingency roles and responsibilities

deny_no_contingency_training contains msg if {
	not input.normalized_data.contingency_training
	msg := "CP-3: No contingency training program configured"
}

deny_personnel_not_trained contains msg if {
	some user in input.normalized_data.users
	user.contingency_role_assigned
	not user.contingency_training_completed
	msg := sprintf("CP-3: User '%s' with contingency role has not completed contingency training", [user.username])
}

deny_training_expired contains msg if {
	some user in input.normalized_data.users
	user.contingency_role_assigned
	user.contingency_training_completed
	user.contingency_training_days > 365
	msg := sprintf("CP-3: User '%s' contingency training expired (%d days since completion)", [user.username, user.contingency_training_days])
}

deny_no_initial_training contains msg if {
	some user in input.normalized_data.users
	user.contingency_role_assigned
	user.role_assignment_days <= 30
	not user.contingency_training_completed
	msg := sprintf("CP-3: User '%s' recently assigned contingency role but has not received initial training", [user.username])
}

deny_no_training_after_change contains msg if {
	input.normalized_data.contingency_training
	input.normalized_data.contingency_training.system_change_detected
	not input.normalized_data.contingency_training.retraining_completed
	msg := "CP-3: System changes detected but contingency retraining has not been completed"
}

default compliant := false

compliant if {
	count(deny_no_contingency_training) == 0
	count(deny_personnel_not_trained) == 0
	count(deny_training_expired) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_contingency_training],
		[f | some f in deny_personnel_not_trained],
	),
	array.concat(
		[f | some f in deny_training_expired],
		array.concat(
			[f | some f in deny_no_initial_training],
			[f | some f in deny_no_training_after_change],
		),
	),
)

result := {
	"control_id": "CP-3",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
