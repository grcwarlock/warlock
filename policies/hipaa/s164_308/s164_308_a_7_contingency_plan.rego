package hipaa.s164_308.s164_308_a_7

import rego.v1

# 164.308(a)(7): Contingency Plan
# Requires policies and procedures for responding to an emergency or
# other occurrence that damages systems containing ePHI

deny_no_contingency_plan contains msg if {
	not input.normalized_data.policies.contingency_plan_exists
	msg := "164.308(a)(7): No contingency plan exists for systems containing ePHI"
}

deny_no_data_backup_plan contains msg if {
	not input.normalized_data.config.backup_enabled
	msg := "164.308(a)(7): Data backup plan is not implemented — must create and maintain retrievable exact copies of ePHI"
}

deny_backup_not_tested contains msg if {
	input.normalized_data.config.backup_enabled
	not input.normalized_data.config.backup_tested
	msg := "164.308(a)(7): Backup restoration has not been tested — must verify recoverability of ePHI"
}

deny_no_disaster_recovery contains msg if {
	not input.normalized_data.policies.disaster_recovery_plan
	msg := "164.308(a)(7): No disaster recovery plan — must establish procedures to restore any loss of ePHI data"
}

default compliant := false

compliant if {
	count(deny_no_contingency_plan) == 0
	count(deny_no_data_backup_plan) == 0
	count(deny_backup_not_tested) == 0
	count(deny_no_disaster_recovery) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_contingency_plan],
		[f | some f in deny_no_data_backup_plan],
	),
	array.concat(
		[f | some f in deny_backup_not_tested],
		[f | some f in deny_no_disaster_recovery],
	),
)

result := {
	"control_id": "164.308(a)(7)",
	"compliant": compliant,
	"findings": findings,
	"severity": "critical",
}
