package cmmc.ia.ia_l2_3_5_1

import rego.v1

# IA.L2-3.5.1: Identification
# Identify system users, processes acting on behalf of users, and devices

deny_no_unique_id contains msg if {
	some user in input.normalized_data.users
	user.shared_account
	msg := sprintf("IA.L2-3.5.1: Account '%s' is shared — all users must be uniquely identified", [user.username])
}

deny_no_device_identification contains msg if {
	some device in input.normalized_data.devices
	not device.identified
	not device.certificate_bound
	msg := sprintf("IA.L2-3.5.1: Device '%s' is not uniquely identified or certificate-bound before network access", [device.name])
}

deny_service_account_no_owner contains msg if {
	some user in input.normalized_data.users
	user.service_account
	not user.owner_assigned
	msg := sprintf("IA.L2-3.5.1: Service account '%s' does not have an assigned owner", [user.username])
}

default compliant := false

compliant if {
	count(deny_no_unique_id) == 0
	count(deny_no_device_identification) == 0
	count(deny_service_account_no_owner) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_unique_id],
		[f | some f in deny_no_device_identification],
	),
	[f | some f in deny_service_account_no_owner],
)

result := {
	"control_id": "IA.L2-3.5.1",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
