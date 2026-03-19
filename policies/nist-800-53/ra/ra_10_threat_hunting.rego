package nist.ra.ra_10

import rego.v1

# RA-10: Threat Hunting

deny_no_threat_hunting contains msg if {
	not input.normalized_data.threat_hunting
	msg := "RA-10: No threat hunting capability established"
}

deny_no_threat_hunting_team contains msg if {
	th := input.normalized_data.threat_hunting
	not th.dedicated_team
	msg := "RA-10: No dedicated threat hunting team or assigned personnel"
}

deny_no_threat_intelligence contains msg if {
	th := input.normalized_data.threat_hunting
	not th.threat_intelligence_feeds
	msg := "RA-10: No threat intelligence feeds integrated into threat hunting activities"
}

deny_hunting_not_conducted contains msg if {
	th := input.normalized_data.threat_hunting
	th.last_hunt_days > 90
	msg := sprintf("RA-10: Threat hunting activities have not been conducted in %d days", [th.last_hunt_days])
}

deny_no_hunting_methodology contains msg if {
	th := input.normalized_data.threat_hunting
	not th.methodology_defined
	msg := "RA-10: No threat hunting methodology or playbooks defined"
}

deny_findings_not_actioned contains msg if {
	th := input.normalized_data.threat_hunting
	some finding in th.findings
	not finding.actioned
	msg := sprintf("RA-10: Threat hunting finding '%s' has not been actioned", [finding.id])
}

default compliant := false

compliant if {
	count(deny_no_threat_hunting) == 0
	count(deny_no_threat_hunting_team) == 0
	count(deny_no_threat_intelligence) == 0
	count(deny_hunting_not_conducted) == 0
	count(deny_no_hunting_methodology) == 0
	count(deny_findings_not_actioned) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_threat_hunting],
		[f | some f in deny_no_threat_hunting_team],
	),
	array.concat(
		array.concat(
			[f | some f in deny_no_threat_intelligence],
			[f | some f in deny_hunting_not_conducted],
		),
		array.concat(
			[f | some f in deny_no_hunting_methodology],
			[f | some f in deny_findings_not_actioned],
		),
	),
)

result := {
	"control_id": "RA-10",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
