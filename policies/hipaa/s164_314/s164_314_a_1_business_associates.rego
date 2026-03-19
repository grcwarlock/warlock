package hipaa.s164_314.s164_314_a_1

import rego.v1

# 164.314(a)(1): Business Associate Contracts or Other Arrangements
# Requires covered entities to obtain satisfactory assurances from
# business associates that they will safeguard ePHI

deny_no_baa_policy contains msg if {
	not input.normalized_data.policies.business_associate_policy
	msg := "164.314(a)(1): No business associate agreement policy — must require BAAs with all entities that create, receive, maintain, or transmit ePHI on behalf of the covered entity"
}

deny_missing_baa contains msg if {
	some associate in input.normalized_data.resources.business_associates
	not associate.baa_signed
	msg := sprintf("164.314(a)(1): Business associate '%s' does not have a signed BAA", [associate.name])
}

deny_expired_baa contains msg if {
	some associate in input.normalized_data.resources.business_associates
	associate.baa_signed
	associate.baa_expired
	msg := sprintf("164.314(a)(1): Business associate '%s' BAA has expired and requires renewal", [associate.name])
}

deny_no_baa_inventory contains msg if {
	not input.normalized_data.policies.business_associate_inventory_maintained
	msg := "164.314(a)(1): No business associate inventory maintained — must track all entities with access to ePHI"
}

default compliant := false

compliant if {
	count(deny_no_baa_policy) == 0
	count(deny_missing_baa) == 0
	count(deny_expired_baa) == 0
	count(deny_no_baa_inventory) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_baa_policy],
		[f | some f in deny_missing_baa],
	),
	array.concat(
		[f | some f in deny_expired_baa],
		[f | some f in deny_no_baa_inventory],
	),
)

result := {
	"control_id": "164.314(a)(1)",
	"compliant": compliant,
	"findings": findings,
	"severity": "critical",
}
