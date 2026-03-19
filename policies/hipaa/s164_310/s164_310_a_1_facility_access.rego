package hipaa.s164_310.s164_310_a_1

import rego.v1

# 164.310(a)(1): Facility Access Controls
# Requires policies and procedures to limit physical access to electronic
# information systems and the facilities in which they are housed

deny_no_facility_access_policy contains msg if {
	not input.normalized_data.policies.facility_access_controls
	msg := "164.310(a)(1): No facility access control policy exists — must limit physical access to systems housing ePHI"
}

deny_no_visitor_log contains msg if {
	not input.normalized_data.config.visitor_access_logging_enabled
	msg := "164.310(a)(1): Visitor access logging is not enabled for facilities containing ePHI systems"
}

deny_no_facility_security_plan contains msg if {
	not input.normalized_data.policies.facility_security_plan
	msg := "164.310(a)(1): No facility security plan — must document safeguards to protect facilities and equipment from unauthorized access and tampering"
}

deny_no_maintenance_records contains msg if {
	not input.normalized_data.policies.maintenance_records_documented
	msg := "164.310(a)(1): Physical security maintenance records are not documented"
}

default compliant := false

compliant if {
	count(deny_no_facility_access_policy) == 0
	count(deny_no_visitor_log) == 0
	count(deny_no_facility_security_plan) == 0
	count(deny_no_maintenance_records) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_facility_access_policy],
		[f | some f in deny_no_visitor_log],
	),
	array.concat(
		[f | some f in deny_no_facility_security_plan],
		[f | some f in deny_no_maintenance_records],
	),
)

result := {
	"control_id": "164.310(a)(1)",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
