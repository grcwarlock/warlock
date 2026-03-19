package cmmc.ps.ps_l2_3_9_1

import rego.v1

# PS.L2-3.9.1: Personnel Screening
# Screen individuals prior to authorizing access to organizational systems containing CUI

deny_no_background_check contains msg if {
	some user in input.normalized_data.users
	user.cui_access
	not user.background_check_completed
	msg := sprintf("PS.L2-3.9.1: User '%s' has CUI access but has not completed a background check", [user.username])
}

deny_expired_screening contains msg if {
	some user in input.normalized_data.users
	user.cui_access
	user.background_check_completed
	user.screening_age_days > 1825
	msg := sprintf("PS.L2-3.9.1: User '%s' background screening is over 5 years old — rescreening required", [user.username])
}

deny_no_termination_process contains msg if {
	some user in input.normalized_data.users
	user.employment_status == "terminated"
	user.enabled
	msg := sprintf("PS.L2-3.9.1: Terminated user '%s' still has an active system account", [user.username])
}

default compliant := false

compliant if {
	count(deny_no_background_check) == 0
	count(deny_expired_screening) == 0
	count(deny_no_termination_process) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_background_check],
		[f | some f in deny_expired_screening],
	),
	[f | some f in deny_no_termination_process],
)

result := {
	"control_id": "PS.L2-3.9.1",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
