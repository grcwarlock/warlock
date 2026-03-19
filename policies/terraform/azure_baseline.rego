package terraform.azure

import rego.v1

# Terraform plan-time compliance for Azure resources

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "azurerm_storage_account"
	not resource.change.after.enable_https_traffic_only
	msg := sprintf("Storage account '%s' must enforce HTTPS [SC-8]", [resource.name])
}

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "azurerm_network_security_rule"
	resource.change.after.direction == "Inbound"
	resource.change.after.access == "Allow"
	resource.change.after.source_address_prefix == "*"
	resource.change.after.destination_port_range == "22"
	msg := sprintf("NSG rule '%s' allows SSH from any source [SC-7]", [resource.name])
}

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "azurerm_network_security_rule"
	resource.change.after.direction == "Inbound"
	resource.change.after.access == "Allow"
	resource.change.after.source_address_prefix == "*"
	resource.change.after.destination_port_range == "3389"
	msg := sprintf("NSG rule '%s' allows RDP from any source [SC-7]", [resource.name])
}

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "azurerm_mssql_server"
	not resource.change.after.auditing_policy
	msg := sprintf("SQL Server '%s' must have auditing enabled [AU-2]", [resource.name])
}

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "azurerm_key_vault"
	not resource.change.after.purge_protection_enabled
	msg := sprintf("Key Vault '%s' must have purge protection [SC-12]", [resource.name])
}
