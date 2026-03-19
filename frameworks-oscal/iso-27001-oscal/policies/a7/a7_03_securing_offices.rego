package iso_27001.a7.a7_03

import rego.v1

# A.7.3: Securing Offices, Rooms and Facilities
# Validates facility security through network segmentation for sensitive zones

deny_no_restricted_vpc contains msg if {
	not input.normalized_data.vpcs_have_restricted_zones
	msg := "A.7.3: No VPC is tagged as a restricted zone for sensitive workloads"
}

deny_restricted_vpc_public_subnets contains msg if {
	some vpc in input.normalized_data.vpcs
	vpc.tags.Zone == "Restricted"
	some subnet in vpc.subnets
	subnet.map_public_ip_on_launch
	msg := sprintf("A.7.3: Restricted VPC '%s' has public subnet '%s' — should be private only", [vpc.id, subnet.id])
}

deny_no_facility_security_plan contains msg if {
	not input.normalized_data.policies.facility_security_plan_documented
	msg := "A.7.3: No facility security plan documented"
}

deny_restricted_vpc_no_nacl contains msg if {
	some vpc in input.normalized_data.vpcs
	vpc.tags.Zone == "Restricted"
	not vpc.custom_nacl_configured
	msg := sprintf("A.7.3: Restricted VPC '%s' uses default NACL — custom network ACLs required", [vpc.id])
}

default compliant := false

compliant if {
	count(deny_no_restricted_vpc) == 0
	count(deny_restricted_vpc_public_subnets) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_restricted_vpc],
		[f | some f in deny_restricted_vpc_public_subnets],
	),
	array.concat(
		[f | some f in deny_no_facility_security_plan],
		[f | some f in deny_restricted_vpc_no_nacl],
	),
)

result := {
	"control_id": "A.7.3",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
