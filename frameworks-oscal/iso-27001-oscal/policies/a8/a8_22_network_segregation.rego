package iso_27001.a8.a8_22

import rego.v1

# A.8.22: Segregation of Networks
# Validates network segregation through VPCs, subnets, and security groups

deny_single_vpc contains msg if {
	count(input.normalized_data.vpcs) == 1
	msg := "A.8.22: Only one VPC exists — network segregation not implemented"
}

deny_no_subnet_segregation contains msg if {
	some vpc in input.normalized_data.vpcs
	not vpc.has_private_subnets
	msg := sprintf("A.8.22: VPC '%s' has no private subnets — no tier segregation", [vpc.id])
}

deny_no_environment_tags contains msg if {
	some vpc in input.normalized_data.vpcs
	not vpc.tags.Environment
	msg := sprintf("A.8.22: VPC '%s' is not tagged with Environment — segregation purpose unclear", [vpc.id])
}

deny_uncontrolled_peering contains msg if {
	some peering in input.normalized_data.vpc_peering.connections
	not peering.has_route_restrictions
	msg := sprintf("A.8.22: VPC peering '%s' has no route restrictions — full network access between VPCs", [peering.id])
}

default compliant := false

compliant if {
	count(deny_single_vpc) == 0
	count(deny_no_subnet_segregation) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_single_vpc],
		[f | some f in deny_no_subnet_segregation],
	),
	array.concat(
		[f | some f in deny_no_environment_tags],
		[f | some f in deny_uncontrolled_peering],
	),
)

result := {
	"control_id": "A.8.22",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
