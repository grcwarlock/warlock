package warlock.iso_27701.transfer

import rego.v1

# ISO 27701 Data Transfer Controls
# 7.5.1-7.5.4: PII transfer, disclosure, and sharing

# 7.5.1: Cross-border transfer — identify legal basis
deny_no_transfer_basis contains msg if {
	some transfer in input.normalized_data.privacy.cross_border_transfers
	not transfer.legal_basis_documented
	msg := sprintf("7.5.1: Cross-border transfer to '%s' — no documented legal basis", [transfer.destination])
}

# 7.5.2: Countries and organizations to which PII may be transferred
deny_no_transfer_inventory contains msg if {
	not input.normalized_data.privacy.transfer_inventory_maintained
	msg := "7.5.2: No inventory of countries/organizations where PII is transferred"
}

# 7.5.3: Records of PII disclosure to third parties
deny_no_disclosure_records contains msg if {
	not input.normalized_data.privacy.disclosure_records_maintained
	msg := "7.5.3: No records of PII disclosures to third parties"
}

# 7.5.4: Notification of changes to PII transfer arrangements
deny_no_change_notification contains msg if {
	some transfer in input.normalized_data.privacy.cross_border_transfers
	transfer.arrangements_changed
	not transfer.change_notification_sent
	msg := sprintf("7.5.4: Transfer to '%s' — arrangements changed without notification", [transfer.destination])
}

default compliant := false

compliant if {
	count(deny_no_transfer_basis) == 0
	count(deny_no_transfer_inventory) == 0
	count(deny_no_disclosure_records) == 0
	count(deny_no_change_notification) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_transfer_basis],
		[f | some f in deny_no_transfer_inventory],
	),
	array.concat(
		[f | some f in deny_no_disclosure_records],
		[f | some f in deny_no_change_notification],
	),
)

result := {
	"control_id": "7.5",
	"framework": "ISO 27701",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
