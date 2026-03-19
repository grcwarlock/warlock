package nist.pe.pe_17

import rego.v1

# PE-17: Alternate Work Site

deny_no_alternate_site_policy contains msg if {
	not input.normalized_data.physical_security.alternate_work_site_policy_defined
	msg := "PE-17: Organization has not defined an alternate work site (remote work) security policy"
}

deny_site_no_security_controls contains msg if {
	some site in input.normalized_data.physical_security.alternate_work_sites
	not site.security_controls_implemented
	msg := sprintf("PE-17: Alternate work site '%s' does not have required security controls implemented", [site.site_id])
}

deny_no_vpn_required contains msg if {
	some site in input.normalized_data.physical_security.alternate_work_sites
	not site.vpn_required
	msg := sprintf("PE-17: Alternate work site '%s' does not require VPN for remote access", [site.site_id])
}

deny_site_not_assessed contains msg if {
	some site in input.normalized_data.physical_security.alternate_work_sites
	not site.security_assessment_completed
	msg := sprintf("PE-17: Alternate work site '%s' has not completed a security assessment", [site.site_id])
}

deny_no_secure_communication contains msg if {
	some site in input.normalized_data.physical_security.alternate_work_sites
	not site.secure_communication_channels
	msg := sprintf("PE-17: Alternate work site '%s' does not have secure communication channels established", [site.site_id])
}

default compliant := false

compliant if {
	count(deny_no_alternate_site_policy) == 0
	count(deny_site_no_security_controls) == 0
	count(deny_no_vpn_required) == 0
	count(deny_site_not_assessed) == 0
	count(deny_no_secure_communication) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_alternate_site_policy],
		[f | some f in deny_site_no_security_controls],
	),
	array.concat(
		array.concat(
			[f | some f in deny_no_vpn_required],
			[f | some f in deny_site_not_assessed],
		),
		[f | some f in deny_no_secure_communication],
	),
)

result := {
	"control_id": "PE-17",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
