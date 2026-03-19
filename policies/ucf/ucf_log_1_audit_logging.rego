package ucf.log.ucf_log_1

import rego.v1

# UCF-LOG-1: Audit Logging
# Validates that audit logging is enabled and properly configured

deny_no_cloudtrail contains msg if {
	not input.normalized_data.cloudtrail.enabled
	msg := "UCF-LOG-1: CloudTrail audit logging is not enabled"
}

deny_not_multi_region contains msg if {
	input.normalized_data.cloudtrail.enabled
	not input.normalized_data.cloudtrail.multi_region
	msg := "UCF-LOG-1: CloudTrail is not configured for multi-region logging"
}

default compliant := false

compliant if {
	count(deny_no_cloudtrail) == 0
	count(deny_not_multi_region) == 0
}

findings := array.concat(
	[f | some f in deny_no_cloudtrail],
	[f | some f in deny_not_multi_region],
)

result := {
	"control_id": "UCF-LOG-1",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
