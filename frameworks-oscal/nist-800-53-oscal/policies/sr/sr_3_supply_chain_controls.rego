package nist.sr.sr_3

import rego.v1

# SR-3: Supply Chain Controls and Processes

deny_no_supply_chain_controls contains msg if {
	not input.normalized_data.supply_chain_controls
	msg := "SR-3: No supply chain controls and processes established"
}

deny_no_provenance_tracking contains msg if {
	scc := input.normalized_data.supply_chain_controls
	not scc.provenance_tracking
	msg := "SR-3: No provenance tracking for system components"
}

deny_no_supplier_diversity contains msg if {
	scc := input.normalized_data.supply_chain_controls
	not scc.supplier_diversity_considered
	msg := "SR-3: Supplier diversity not considered to reduce single points of failure"
}

deny_no_counterfeit_prevention contains msg if {
	scc := input.normalized_data.supply_chain_controls
	not scc.counterfeit_prevention
	msg := "SR-3: No counterfeit component prevention measures established"
}

deny_controls_not_assessed contains msg if {
	scc := input.normalized_data.supply_chain_controls
	scc.last_assessment_days > 365
	msg := sprintf("SR-3: Supply chain controls have not been assessed in %d days", [scc.last_assessment_days])
}

default compliant := false

compliant if {
	count(deny_no_supply_chain_controls) == 0
	count(deny_no_provenance_tracking) == 0
	count(deny_no_supplier_diversity) == 0
	count(deny_no_counterfeit_prevention) == 0
	count(deny_controls_not_assessed) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_supply_chain_controls],
		[f | some f in deny_no_provenance_tracking],
	),
	array.concat(
		[f | some f in deny_no_supplier_diversity],
		array.concat(
			[f | some f in deny_no_counterfeit_prevention],
			[f | some f in deny_controls_not_assessed],
		),
	),
)

result := {
	"control_id": "SR-3",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
