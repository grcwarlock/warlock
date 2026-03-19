package terraform.azure_test

import rego.v1

import data.terraform.azure

test_compliant_storage_https if {
	count(azure.deny) == 0 with input as {"resource_changes": [{
		"type": "azurerm_storage_account",
		"name": "good-sa",
		"change": {"after": {"enable_https_traffic_only": true}},
	}]}
}

test_noncompliant_storage_no_https if {
	count(azure.deny) > 0 with input as {"resource_changes": [{
		"type": "azurerm_storage_account",
		"name": "bad-sa",
		"change": {"after": {}},
	}]}
}

test_noncompliant_nsg_ssh_open if {
	count(azure.deny) > 0 with input as {"resource_changes": [{
		"type": "azurerm_network_security_rule",
		"name": "bad-nsg",
		"change": {"after": {"direction": "Inbound", "access": "Allow", "source_address_prefix": "*", "destination_port_range": "22"}},
	}]}
}
