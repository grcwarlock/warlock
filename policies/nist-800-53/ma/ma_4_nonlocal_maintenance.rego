package nist.ma.ma_4

import rego.v1

# MA-4: Nonlocal Maintenance

deny_remote_no_encryption contains msg if {
	some session in input.normalized_data.maintenance.remote_sessions
	not session.encrypted
	msg := sprintf("MA-4: Remote maintenance session '%s' to '%s' does not use encrypted communications", [session.session_id, session.target_system])
}

deny_remote_no_mfa contains msg if {
	some session in input.normalized_data.maintenance.remote_sessions
	not session.mfa_used
	msg := sprintf("MA-4: Remote maintenance session '%s' did not use multi-factor authentication", [session.session_id])
}

deny_remote_no_audit contains msg if {
	some session in input.normalized_data.maintenance.remote_sessions
	not session.audited
	msg := sprintf("MA-4: Remote maintenance session '%s' was not audited or recorded", [session.session_id])
}

deny_remote_not_authorized contains msg if {
	some session in input.normalized_data.maintenance.remote_sessions
	not session.pre_authorized
	msg := sprintf("MA-4: Remote maintenance session '%s' was not pre-authorized before initiation", [session.session_id])
}

deny_remote_session_not_terminated contains msg if {
	some session in input.normalized_data.maintenance.remote_sessions
	session.status == "active"
	not session.within_approved_window
	msg := sprintf("MA-4: Remote maintenance session '%s' is active outside approved maintenance window", [session.session_id])
}

default compliant := false

compliant if {
	count(deny_remote_no_encryption) == 0
	count(deny_remote_no_mfa) == 0
	count(deny_remote_no_audit) == 0
	count(deny_remote_not_authorized) == 0
	count(deny_remote_session_not_terminated) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_remote_no_encryption],
		[f | some f in deny_remote_no_mfa],
	),
	array.concat(
		array.concat(
			[f | some f in deny_remote_no_audit],
			[f | some f in deny_remote_not_authorized],
		),
		[f | some f in deny_remote_session_not_terminated],
	),
)

result := {
	"control_id": "MA-4",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
