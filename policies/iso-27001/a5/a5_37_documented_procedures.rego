package iso_27001.a5.a5_37

import rego.v1

# A.5.37: Documented Operating Procedures
# Validates operating procedures are documented and accessible

deny_no_ssm_runbooks contains msg if {
	not input.normalized_data.ssm.operational_runbooks_exist
	msg := "A.5.37: No SSM Automation runbooks exist for documented operating procedures"
}

deny_runbooks_not_shared contains msg if {
	some doc in input.normalized_data.ssm.documents
	doc.document_type == "Automation"
	not doc.shared
	msg := sprintf("A.5.37: SSM document '%s' is not shared with operations team", [doc.name])
}

deny_no_procedures_stored contains msg if {
	not input.normalized_data.policies.operating_procedures_stored
	msg := "A.5.37: No operating procedures stored in accessible document repository"
}

deny_procedures_outdated contains msg if {
	some procedure in input.normalized_data.policies.operating_procedures
	procedure.last_review_days > 365
	msg := sprintf("A.5.37: Operating procedure '%s' has not been reviewed in %d days", [procedure.name, procedure.last_review_days])
}

default compliant := false

compliant if {
	count(deny_no_ssm_runbooks) == 0
	count(deny_no_procedures_stored) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_ssm_runbooks],
		[f | some f in deny_runbooks_not_shared],
	),
	array.concat(
		[f | some f in deny_no_procedures_stored],
		[f | some f in deny_procedures_outdated],
	),
)

result := {
	"control_id": "A.5.37",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
