package iso_27001.a8.a8_31

import rego.v1

# A.8.31: Separation of Development, Test and Production Environments
# Validates environment separation through accounts or VPCs

deny_no_separate_accounts contains msg if {
	not input.normalized_data.organization.separate_accounts_per_environment
	msg := "A.8.31: No separate AWS accounts for dev/test/prod environment separation"
}

deny_vpcs_no_environment_tag contains msg if {
	some vpc in input.normalized_data.vpcs
	not vpc.tags.Environment
	msg := sprintf("A.8.31: VPC '%s' is not tagged with Environment — separation unclear", [vpc.id])
}

deny_no_env_separation_scp contains msg if {
	not input.normalized_data.organization.env_separation_scp_exists
	msg := "A.8.31: No SCP prevents cross-environment access between dev and production"
}

deny_single_account_no_vpc_separation contains msg if {
	not input.normalized_data.organization.separate_accounts_per_environment
	count(input.normalized_data.vpcs) == 1
	msg := "A.8.31: Single account with single VPC — no environment separation"
}

deny_resources_no_environment_tag contains msg if {
	some resource in input.normalized_data.resources
	not resource.tags.Environment
	msg := sprintf("A.8.31: Resource '%s' (%s) missing Environment tag", [resource.id, resource.type])
}

default compliant := false

compliant if {
	count(deny_no_separate_accounts) == 0
	count(deny_vpcs_no_environment_tag) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_separate_accounts],
		[f | some f in deny_vpcs_no_environment_tag],
	),
	array.concat(
		[f | some f in deny_no_env_separation_scp],
		array.concat(
			[f | some f in deny_single_account_no_vpc_separation],
			[f | some f in deny_resources_no_environment_tag],
		),
	),
)

result := {
	"control_id": "A.8.31",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
