package hipaa.s164_310.s164_310_d_1

import rego.v1

# 164.310(d)(1): Device and Media Controls
# Requires policies and procedures governing the receipt and removal of
# hardware and electronic media containing ePHI

deny_no_media_disposal_policy contains msg if {
	not input.normalized_data.policies.media_disposal_policy
	msg := "164.310(d)(1): No media disposal policy — must address final disposition of ePHI and hardware it is stored on"
}

deny_no_media_reuse_procedure contains msg if {
	not input.normalized_data.policies.media_reuse_procedure
	msg := "164.310(d)(1): No media reuse procedure — must ensure ePHI is removed before media is reused"
}

deny_unencrypted_removable_media contains msg if {
	some device in input.normalized_data.resources.media_devices
	device.removable
	not device.encrypted
	msg := sprintf("164.310(d)(1): Removable media device '%s' is not encrypted", [device.name])
}

deny_no_hardware_inventory contains msg if {
	not input.normalized_data.config.hardware_inventory_maintained
	msg := "164.310(d)(1): No hardware inventory maintained — must track movement of hardware and electronic media containing ePHI"
}

default compliant := false

compliant if {
	count(deny_no_media_disposal_policy) == 0
	count(deny_no_media_reuse_procedure) == 0
	count(deny_unencrypted_removable_media) == 0
	count(deny_no_hardware_inventory) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_media_disposal_policy],
		[f | some f in deny_no_media_reuse_procedure],
	),
	array.concat(
		[f | some f in deny_unencrypted_removable_media],
		[f | some f in deny_no_hardware_inventory],
	),
)

result := {
	"control_id": "164.310(d)(1)",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
