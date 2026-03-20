package pci_dss.r3

import rego.v1

# PCI DSS 4.0 Requirement 3: Protect Stored Account Data

deny_unencrypted_storage contains msg if {
	some store in input.normalized_data.data_stores
	not store.encryption_enabled
	msg := sprintf("R3.5: Data store '%s' does not have encryption at rest enabled", [store.name])
}

deny_no_key_rotation contains msg if {
	some key in input.normalized_data.encryption_keys
	not key.rotation_enabled
	msg := sprintf("R3.7: Encryption key '%s' does not have automatic rotation enabled", [key.id])
}

deny_sensitive_data_stored contains msg if {
	some store in input.normalized_data.data_stores
	store.contains_pan
	not store.pan_protected
	msg := sprintf("R3.4: Data store '%s' contains PAN without adequate protection", [store.name])
}

default compliant := false

compliant if {
	count(deny_unencrypted_storage) == 0
	count(deny_no_key_rotation) == 0
	count(deny_sensitive_data_stored) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_unencrypted_storage],
		[f | some f in deny_no_key_rotation],
	),
	[f | some f in deny_sensitive_data_stored],
)

result := {
	"control_id": "R3",
	"framework": "PCI DSS 4.0",
	"compliant": compliant,
	"findings": findings,
	"severity": "critical",
}
