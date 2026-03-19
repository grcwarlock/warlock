package ucf.asm.ucf_asm_1

import rego.v1

# UCF-ASM-1: Asset Inventory
# Validates that asset inventory is maintained

deny_no_endpoints contains msg if {
	count(input.normalized_data.endpoints) == 0
	count(input.normalized_data.devices) == 0
	msg := "UCF-ASM-1: No endpoint or device inventory data available"
}

deny_no_users contains msg if {
	count(input.normalized_data.users) == 0
	msg := "UCF-ASM-1: No user identity inventory data available"
}

default compliant := false

compliant if {
	count(deny_no_endpoints) == 0
	count(deny_no_users) == 0
}

findings := array.concat(
	[f | some f in deny_no_endpoints],
	[f | some f in deny_no_users],
)

result := {
	"control_id": "UCF-ASM-1",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
