package iso_27001.a5.a5_10

import rego.v1

# A.5.10: Acceptable Use of Information and Other Associated Assets
# Validates acceptable use policies are enforced through technical controls

deny_no_region_restriction contains msg if {
	not input.normalized_data.organization.region_restriction_scp_exists
	msg := "A.5.10: No SCP restricts resource deployment to approved regions"
}

deny_no_acceptable_use_policy contains msg if {
	not input.normalized_data.policies.acceptable_use_policy
	msg := "A.5.10: No acceptable use policy is documented"
}

deny_unapproved_instance_types contains msg if {
	not input.normalized_data.config.allowed_instance_types_rule_exists
	msg := "A.5.10: No AWS Config rule enforces allowed instance types"
}

deny_no_scps contains msg if {
	count(input.normalized_data.organization.scps) == 0
	msg := "A.5.10: No Service Control Policies exist to enforce acceptable use boundaries"
}

default compliant := false

compliant if {
	count(deny_no_region_restriction) == 0
	count(deny_no_acceptable_use_policy) == 0
	count(deny_no_scps) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_region_restriction],
		[f | some f in deny_no_acceptable_use_policy],
	),
	array.concat(
		[f | some f in deny_unapproved_instance_types],
		[f | some f in deny_no_scps],
	),
)

result := {
	"control_id": "A.5.10",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
