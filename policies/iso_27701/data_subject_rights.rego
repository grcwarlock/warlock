package warlock.iso_27701.dsr

import rego.v1

# ISO 27701 Data Subject Rights
# 7.3.2-7.3.10: Individual rights management

# 7.3.2: Access request handling
deny_no_access_process contains msg if {
	not input.normalized_data.privacy.dsr_access_process
	msg := "7.3.2: No process for handling data subject access requests"
}

# 7.3.3: Rectification process
deny_no_rectification contains msg if {
	not input.normalized_data.privacy.dsr_rectification_process
	msg := "7.3.3: No process for data rectification requests"
}

# 7.3.5: Erasure/right to be forgotten process
deny_no_erasure contains msg if {
	not input.normalized_data.privacy.dsr_erasure_process
	msg := "7.3.5: No process for data erasure requests"
}

# 7.3.6: Portability — provide data in structured format
deny_no_portability contains msg if {
	not input.normalized_data.privacy.dsr_portability_supported
	msg := "7.3.6: Data portability not supported — cannot provide PII in structured format"
}

# 7.3.9: Response timeframe — comply within regulatory deadlines
deny_overdue_requests contains msg if {
	some request in input.normalized_data.privacy.dsr_requests
	not request.completed
	request.days_since_receipt > 30
	msg := sprintf("7.3.9: DSR '%s' overdue — %d days since receipt (30-day SLA)", [request.id, request.days_since_receipt])
}

default compliant := false

compliant if {
	count(deny_no_access_process) == 0
	count(deny_no_rectification) == 0
	count(deny_no_erasure) == 0
	count(deny_no_portability) == 0
	count(deny_overdue_requests) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_access_process],
		[f | some f in deny_no_rectification],
	),
	array.concat(
		array.concat(
			[f | some f in deny_no_erasure],
			[f | some f in deny_no_portability],
		),
		[f | some f in deny_overdue_requests],
	),
)

result := {
	"control_id": "7.3",
	"framework": "ISO 27701",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
