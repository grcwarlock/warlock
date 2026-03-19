package ucf.epp.ucf_epp_1

import rego.v1

# UCF-EPP-1: Endpoint Protection
# Validates EDR agent coverage across endpoints

deny_no_endpoints contains msg if {
	count(input.normalized_data.endpoints) == 0
	msg := "UCF-EPP-1: No endpoint protection agents detected"
}

deny_stale_agent contains msg if {
	some ep in input.normalized_data.endpoints
	ep.status != "online"
	ep.status != ""
	msg := sprintf("UCF-EPP-1: Endpoint '%s' agent status is '%s'", [ep.hostname, ep.status])
}

default compliant := false

compliant if {
	count(deny_no_endpoints) == 0
	count(deny_stale_agent) == 0
}

findings := array.concat(
	[f | some f in deny_no_endpoints],
	[f | some f in deny_stale_agent],
)

result := {
	"control_id": "UCF-EPP-1",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
