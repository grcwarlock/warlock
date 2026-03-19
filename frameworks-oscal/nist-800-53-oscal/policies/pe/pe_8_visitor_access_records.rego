package nist.pe.pe_8

import rego.v1

# PE-8: Visitor Access Records

deny_no_visitor_log contains msg if {
	some facility in input.normalized_data.physical_security.facilities
	not facility.visitor_log_maintained
	msg := sprintf("PE-8: Facility '%s' does not maintain visitor access records", [facility.facility_id])
}

deny_visitor_log_not_reviewed contains msg if {
	some facility in input.normalized_data.physical_security.facilities
	facility.visitor_log_maintained
	not facility.visitor_log_reviewed_within_90_days
	msg := sprintf("PE-8: Visitor access records for facility '%s' have not been reviewed within 90 days", [facility.facility_id])
}

deny_visitor_no_escort contains msg if {
	some visitor in input.normalized_data.physical_security.visitors
	not visitor.escorted
	not visitor.escort_exemption
	msg := sprintf("PE-8: Visitor '%s' at facility '%s' is not being escorted and has no escort exemption", [visitor.visitor_id, visitor.facility_id])
}

deny_visitor_log_retention contains msg if {
	some facility in input.normalized_data.physical_security.facilities
	facility.visitor_log_maintained
	facility.visitor_log_retention_days < 365
	msg := sprintf("PE-8: Visitor log retention at facility '%s' is %d days, which is less than the required 365 days", [facility.facility_id, facility.visitor_log_retention_days])
}

default compliant := false

compliant if {
	count(deny_no_visitor_log) == 0
	count(deny_visitor_log_not_reviewed) == 0
	count(deny_visitor_no_escort) == 0
	count(deny_visitor_log_retention) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_visitor_log],
		[f | some f in deny_visitor_log_not_reviewed],
	),
	array.concat(
		[f | some f in deny_visitor_no_escort],
		[f | some f in deny_visitor_log_retention],
	),
)

result := {
	"control_id": "PE-8",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
