package terraform.kms

import rego.v1

# SC-12: KMS keys must have automatic rotation enabled.
# Use with conftest against a Terraform plan JSON.

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_kms_key"
	_is_create_or_update(resource)
	not resource.change.after.enable_key_rotation
	msg := sprintf("KMS key '%s' must have automatic key rotation enabled [SC-12]", [resource.name])
}

# Keys scheduled for deletion are non-compliant (loss of SC-12 continuity)
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_kms_key"
	_is_delete(resource)
	msg := sprintf("KMS key '%s' is being destroyed — verify SC-12 continuity before proceeding", [resource.name])
}

# Deletion window must be at least 7 days (shortest allowable)
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_kms_key"
	_is_create_or_update(resource)
	resource.change.after.deletion_window_in_days < 7
	msg := sprintf("KMS key '%s' deletion_window_in_days must be >= 7 [SC-12]", [resource.name])
}

# Azure Key Vault: purge protection must be enabled
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "azurerm_key_vault"
	_is_create_or_update(resource)
	not resource.change.after.purge_protection_enabled
	msg := sprintf("Azure Key Vault '%s' must have purge_protection_enabled = true [SC-12]", [resource.name])
}

# Azure Key Vault: RBAC authorization recommended
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "azurerm_key_vault"
	_is_create_or_update(resource)
	not resource.change.after.enable_rbac_authorization
	msg := sprintf("Azure Key Vault '%s' should use RBAC authorization (enable_rbac_authorization = true) [SC-12]", [resource.name])
}

_is_create_or_update(resource) if {
	resource.change.actions[_] in {"create", "update"}
}

_is_delete(resource) if {
	resource.change.actions == ["delete"]
}
