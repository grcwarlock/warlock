package gdpr.art28

import rego.v1

# GDPR Article 28: Processor obligations

deny_no_dpa contains msg if {
	some processor in input.normalized_data.processors
	not processor.dpa_signed
	msg := sprintf("Art28: Processor '%s' does not have a signed Data Processing Agreement", [processor.name])
}

deny_no_access_review contains msg if {
	some processor in input.normalized_data.processors
	processor.days_since_access_review > 90
	msg := sprintf("Art28: Processor '%s' access review overdue (%d days since last review)", [processor.name, processor.days_since_access_review])
}

default compliant := false

compliant if {
	count(deny_no_dpa) == 0
	count(deny_no_access_review) == 0
}

findings := array.concat(
	[f | some f in deny_no_dpa],
	[f | some f in deny_no_access_review],
)

result := {
	"control_id": "Art28",
	"framework": "GDPR",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
