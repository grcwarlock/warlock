package nist.sa.sa_3

import rego.v1

# SA-3: System Development Life Cycle

deny_no_sdlc contains msg if {
	not input.normalized_data.sdlc
	msg := "SA-3: No system development life cycle (SDLC) process defined"
}

deny_sdlc_no_security contains msg if {
	sdlc := input.normalized_data.sdlc
	not sdlc.security_integrated
	msg := "SA-3: Security considerations not integrated into the SDLC"
}

deny_sdlc_no_privacy contains msg if {
	sdlc := input.normalized_data.sdlc
	not sdlc.privacy_integrated
	msg := "SA-3: Privacy considerations not integrated into the SDLC"
}

deny_no_security_roles_sdlc contains msg if {
	sdlc := input.normalized_data.sdlc
	not sdlc.security_roles_defined
	msg := "SA-3: Security roles and responsibilities not defined within the SDLC"
}

deny_sdlc_outdated contains msg if {
	sdlc := input.normalized_data.sdlc
	sdlc.last_review_days > 365
	msg := sprintf("SA-3: SDLC process has not been reviewed in %d days", [sdlc.last_review_days])
}

default compliant := false

compliant if {
	count(deny_no_sdlc) == 0
	count(deny_sdlc_no_security) == 0
	count(deny_sdlc_no_privacy) == 0
	count(deny_no_security_roles_sdlc) == 0
	count(deny_sdlc_outdated) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_sdlc],
		[f | some f in deny_sdlc_no_security],
	),
	array.concat(
		[f | some f in deny_sdlc_no_privacy],
		array.concat(
			[f | some f in deny_no_security_roles_sdlc],
			[f | some f in deny_sdlc_outdated],
		),
	),
)

result := {
	"control_id": "SA-3",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
