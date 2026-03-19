package soc2.cc9

import rego.v1

# SOC 2 CC9: Risk Mitigation
# Risk treatment plans, vendor management, insurance

deny_no_risk_treatment_plans contains msg if {
	not input.normalized_data.governance.risk_treatment_plans_exist
	msg := "CC9.1: No risk treatment plans — identified risks not addressed through mitigation, acceptance, avoidance, or transfer"
}

deny_untreated_risks contains msg if {
	some risk in input.normalized_data.governance.risks
	not risk.treatment_defined
	msg := sprintf("CC9.1: Risk '%s' (severity: %s) has no treatment plan defined", [risk.name, risk.severity])
}

deny_no_vendor_management contains msg if {
	not input.normalized_data.governance.vendor_management_program_exists
	msg := "CC9.2: No vendor management program — third-party risks not assessed and monitored"
}

deny_vendor_no_assessment contains msg if {
	some vendor in input.normalized_data.governance.vendors
	not vendor.risk_assessment_current
	msg := sprintf("CC9.2: Vendor '%s' has no current risk assessment — third-party risk not evaluated", [vendor.name])
}

deny_vendor_no_sla contains msg if {
	some vendor in input.normalized_data.governance.vendors
	vendor.critical
	not vendor.sla_defined
	msg := sprintf("CC9.2: Critical vendor '%s' has no SLA defined — service commitments not contractually established", [vendor.name])
}

deny_no_insurance_coverage contains msg if {
	not input.normalized_data.governance.cyber_insurance_exists
	msg := "CC9.1: No cyber insurance coverage — risk transfer strategy not implemented for residual risks"
}

default compliant := false

compliant if {
	count(deny_no_risk_treatment_plans) == 0
	count(deny_untreated_risks) == 0
	count(deny_no_vendor_management) == 0
	count(deny_vendor_no_assessment) == 0
	count(deny_vendor_no_sla) == 0
	count(deny_no_insurance_coverage) == 0
}

findings := array.concat(
	array.concat(
		array.concat(
			[f | some f in deny_no_risk_treatment_plans],
			[f | some f in deny_untreated_risks],
		),
		array.concat(
			[f | some f in deny_no_vendor_management],
			[f | some f in deny_vendor_no_assessment],
		),
	),
	array.concat(
		[f | some f in deny_vendor_no_sla],
		[f | some f in deny_no_insurance_coverage],
	),
)

result := {
	"control_id": "CC9",
	"framework": "SOC 2",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
