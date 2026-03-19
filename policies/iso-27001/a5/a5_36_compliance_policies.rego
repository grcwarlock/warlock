package iso_27001.a5.a5_36

import rego.v1

# A.5.36: Compliance with Policies, Rules and Standards for Information Security
# Validates compliance monitoring and reporting is active

deny_no_conformance_pack contains msg if {
	not input.normalized_data.config.conformance_packs_exist
	msg := "A.5.36: No AWS Config conformance packs deployed for compliance monitoring"
}

deny_conformance_noncompliant contains msg if {
	some pack in input.normalized_data.config.conformance_packs
	pack.compliance_status != "COMPLIANT"
	msg := sprintf("A.5.36: Conformance pack '%s' has non-compliant rules — review and remediate", [pack.name])
}

deny_no_compliance_dashboard contains msg if {
	not input.normalized_data.cloudwatch.compliance_dashboard_exists
	msg := "A.5.36: No CloudWatch compliance status dashboard for reporting"
}

deny_config_rules_noncompliant contains msg if {
	noncompliant := [r | some r in input.normalized_data.config.rules; r.compliance_type != "COMPLIANT"]
	count(noncompliant) > 0
	msg := sprintf("A.5.36: %d AWS Config rules are non-compliant", [count(noncompliant)])
}

default compliant := false

compliant if {
	count(deny_no_conformance_pack) == 0
	count(deny_conformance_noncompliant) == 0
	count(deny_config_rules_noncompliant) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_conformance_pack],
		[f | some f in deny_conformance_noncompliant],
	),
	array.concat(
		[f | some f in deny_no_compliance_dashboard],
		[f | some f in deny_config_rules_noncompliant],
	),
)

result := {
	"control_id": "A.5.36",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
