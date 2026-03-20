package gdpr.art17

import rego.v1

# GDPR Article 17: Right to erasure (right to be forgotten)

deny_no_erasure_process contains msg if {
	not input.normalized_data.policies.erasure_process_documented
	msg := "Art17: No documented data erasure process — data subjects have right to erasure without undue delay"
}

deny_overdue_erasure_requests contains msg if {
	some request in input.normalized_data.dsar_requests
	request.type == "erasure"
	request.status != "completed"
	request.days_open > 30
	msg := sprintf("Art17: Erasure request '%s' open for %d days — must respond within 30 days", [request.id, request.days_open])
}

default compliant := false

compliant if {
	count(deny_no_erasure_process) == 0
	count(deny_overdue_erasure_requests) == 0
}

findings := array.concat(
	[f | some f in deny_no_erasure_process],
	[f | some f in deny_overdue_erasure_requests],
)

result := {
	"control_id": "Art17",
	"framework": "GDPR",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
