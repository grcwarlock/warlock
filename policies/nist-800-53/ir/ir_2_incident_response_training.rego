package nist.ir.ir_2

import rego.v1

# IR-2: Incident Response Training
# Validates IR training is provided to system users

deny_no_ir_training contains msg if {
	not input.normalized_data.ir_training
	msg := "IR-2: No incident response training program configured"
}

deny_personnel_not_trained contains msg if {
	some user in input.normalized_data.users
	user.ir_role_assigned
	not user.ir_training_completed
	msg := sprintf("IR-2: User '%s' with incident response role has not completed IR training", [user.username])
}

deny_training_expired contains msg if {
	some user in input.normalized_data.users
	user.ir_role_assigned
	user.ir_training_completed
	user.ir_training_days > 365
	msg := sprintf("IR-2: User '%s' incident response training expired (%d days since completion)", [user.username, user.ir_training_days])
}

deny_no_initial_training contains msg if {
	some user in input.normalized_data.users
	user.ir_role_assigned
	user.role_assignment_days <= 30
	not user.ir_training_completed
	msg := sprintf("IR-2: User '%s' recently assigned IR role but has not received initial training", [user.username])
}

deny_no_training_after_change contains msg if {
	input.normalized_data.ir_training
	input.normalized_data.ir_training.system_change_detected
	not input.normalized_data.ir_training.retraining_completed
	msg := "IR-2: System changes detected but incident response retraining has not been completed"
}

deny_no_training_curriculum contains msg if {
	input.normalized_data.ir_training
	not input.normalized_data.ir_training.curriculum_defined
	msg := "IR-2: Incident response training curriculum has not been defined"
}

default compliant := false

compliant if {
	count(deny_no_ir_training) == 0
	count(deny_personnel_not_trained) == 0
	count(deny_training_expired) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_ir_training],
		[f | some f in deny_personnel_not_trained],
	),
	array.concat(
		[f | some f in deny_training_expired],
		array.concat(
			[f | some f in deny_no_initial_training],
			array.concat(
				[f | some f in deny_no_training_after_change],
				[f | some f in deny_no_training_curriculum],
			),
		),
	),
)

result := {
	"control_id": "IR-2",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
