package nist.sr.sr_6

import rego.v1

# SR-6: Supplier Assessments and Reviews

deny_no_supplier_assessments contains msg if {
	not input.normalized_data.supplier_assessments
	msg := "SR-6: No supplier assessment and review process established"
}

deny_supplier_not_assessed contains msg if {
	some supplier in input.normalized_data.suppliers
	supplier.is_critical
	not supplier.assessment_completed
	msg := sprintf("SR-6: Critical supplier '%s' has not been assessed", [supplier.name])
}

deny_assessment_outdated contains msg if {
	some supplier in input.normalized_data.suppliers
	supplier.is_critical
	supplier.assessment_completed
	supplier.days_since_assessment > 365
	msg := sprintf("SR-6: Assessment for supplier '%s' is outdated (%d days since last assessment)", [supplier.name, supplier.days_since_assessment])
}

deny_no_risk_rating contains msg if {
	some supplier in input.normalized_data.suppliers
	supplier.is_critical
	not supplier.risk_rating_assigned
	msg := sprintf("SR-6: No risk rating assigned to critical supplier '%s'", [supplier.name])
}

deny_high_risk_no_mitigation contains msg if {
	some supplier in input.normalized_data.suppliers
	supplier.risk_rating == "high"
	not supplier.mitigation_plan
	msg := sprintf("SR-6: High-risk supplier '%s' has no mitigation plan", [supplier.name])
}

default compliant := false

compliant if {
	count(deny_no_supplier_assessments) == 0
	count(deny_supplier_not_assessed) == 0
	count(deny_assessment_outdated) == 0
	count(deny_no_risk_rating) == 0
	count(deny_high_risk_no_mitigation) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_supplier_assessments],
		[f | some f in deny_supplier_not_assessed],
	),
	array.concat(
		[f | some f in deny_assessment_outdated],
		array.concat(
			[f | some f in deny_no_risk_rating],
			[f | some f in deny_high_risk_no_mitigation],
		),
	),
)

result := {
	"control_id": "SR-6",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
