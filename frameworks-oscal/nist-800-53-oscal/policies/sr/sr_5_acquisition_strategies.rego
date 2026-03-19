package nist.sr.sr_5

import rego.v1

# SR-5: Acquisition Strategies, Tools, and Methods

deny_no_acquisition_strategies contains msg if {
	not input.normalized_data.supply_chain_acquisition
	msg := "SR-5: No supply chain acquisition strategies established"
}

deny_no_approved_vendors contains msg if {
	sca := input.normalized_data.supply_chain_acquisition
	not sca.approved_vendor_list
	msg := "SR-5: No approved vendor list maintained for critical components"
}

deny_no_security_in_acquisition contains msg if {
	sca := input.normalized_data.supply_chain_acquisition
	not sca.security_requirements_in_acquisitions
	msg := "SR-5: Security requirements not included in acquisition strategies"
}

deny_strategies_outdated contains msg if {
	sca := input.normalized_data.supply_chain_acquisition
	sca.last_review_days > 365
	msg := sprintf("SR-5: Acquisition strategies have not been reviewed in %d days", [sca.last_review_days])
}

default compliant := false

compliant if {
	count(deny_no_acquisition_strategies) == 0
	count(deny_no_approved_vendors) == 0
	count(deny_no_security_in_acquisition) == 0
	count(deny_strategies_outdated) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_acquisition_strategies],
		[f | some f in deny_no_approved_vendors],
	),
	array.concat(
		[f | some f in deny_no_security_in_acquisition],
		[f | some f in deny_strategies_outdated],
	),
)

result := {
	"control_id": "SR-5",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
