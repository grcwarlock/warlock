package warlock.iso_27701.transfer_test

import rego.v1

import data.warlock.iso_27701.transfer

test_compliant_transfers if {
	result := transfer.result with input as {"normalized_data": {
		"privacy": {
			"transfer_inventory_maintained": true,
			"disclosure_records_maintained": true,
			"cross_border_transfers": [
				{"destination": "EU", "legal_basis_documented": true, "safeguards_in_place": true, "arrangements_changed": false},
			],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_legal_basis if {
	result := transfer.result with input as {"normalized_data": {
		"privacy": {
			"transfer_inventory_maintained": true,
			"disclosure_records_maintained": true,
			"cross_border_transfers": [
				{"destination": "China", "legal_basis_documented": false, "arrangements_changed": false},
			],
		},
	}}
	result.compliant == false
}

test_changed_without_notification if {
	result := transfer.result with input as {"normalized_data": {
		"privacy": {
			"transfer_inventory_maintained": true,
			"disclosure_records_maintained": true,
			"cross_border_transfers": [
				{"destination": "US", "legal_basis_documented": true, "arrangements_changed": true, "change_notification_sent": false},
			],
		},
	}}
	result.compliant == false
}

test_no_transfer_inventory if {
	result := transfer.result with input as {"normalized_data": {
		"privacy": {
			"transfer_inventory_maintained": false,
			"disclosure_records_maintained": true,
			"cross_border_transfers": [],
		},
	}}
	result.compliant == false
}
