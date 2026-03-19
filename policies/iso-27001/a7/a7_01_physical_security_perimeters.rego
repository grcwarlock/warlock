package iso_27001.a7.a7_01

import rego.v1

# A.7.1: Physical Security Perimeters
# Validates physical security perimeters through region restrictions

deny_no_region_restriction_scp contains msg if {
	not input.normalized_data.organization.region_restriction_scps_exist
	msg := "A.7.1: No SCP restricts deployments to approved regions — physical perimeter not enforced"
}

deny_resources_in_unapproved_region contains msg if {
	approved_regions := input.normalized_data.organization.approved_regions
	some resource in input.normalized_data.resources
	not resource.region in approved_regions
	msg := sprintf("A.7.1: Resource '%s' deployed in unapproved region '%s'", [resource.id, resource.region])
}

deny_no_physical_security_docs contains msg if {
	not input.normalized_data.policies.physical_security_perimeter_documented
	msg := "A.7.1: Physical security perimeter requirements are not documented"
}

deny_scp_not_attached contains msg if {
	input.normalized_data.organization.region_restriction_scps_exist
	not input.normalized_data.organization.region_scp_attached_to_all_ous
	msg := "A.7.1: Region restriction SCP exists but is not attached to all organizational units"
}

default compliant := false

compliant if {
	count(deny_no_region_restriction_scp) == 0
	count(deny_resources_in_unapproved_region) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_region_restriction_scp],
		[f | some f in deny_resources_in_unapproved_region],
	),
	array.concat(
		[f | some f in deny_no_physical_security_docs],
		[f | some f in deny_scp_not_attached],
	),
)

result := {
	"control_id": "A.7.1",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
