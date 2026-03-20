package terraform.kms_test

import rego.v1

import data.terraform.kms

# ── aws_kms_key tests ─────────────────────────────────────────────────

test_kms_key_rotation_enabled_compliant if {
	count(kms.deny) == 0 with input as {"resource_changes": [{
		"type": "aws_kms_key",
		"name": "good-key",
		"change": {
			"actions": ["create"],
			"after": {
				"enable_key_rotation": true,
				"deletion_window_in_days": 30,
			},
		},
	}]}
}

test_kms_key_rotation_disabled_noncompliant if {
	count(kms.deny) > 0 with input as {"resource_changes": [{
		"type": "aws_kms_key",
		"name": "bad-key",
		"change": {
			"actions": ["create"],
			"after": {
				"enable_key_rotation": false,
				"deletion_window_in_days": 30,
			},
		},
	}]}
}

test_kms_key_short_deletion_window_noncompliant if {
	count(kms.deny) > 0 with input as {"resource_changes": [{
		"type": "aws_kms_key",
		"name": "short-window-key",
		"change": {
			"actions": ["create"],
			"after": {
				"enable_key_rotation": true,
				"deletion_window_in_days": 3,
			},
		},
	}]}
}

# ── azurerm_key_vault tests ───────────────────────────────────────────

test_key_vault_purge_protection_compliant if {
	count(kms.deny) == 0 with input as {"resource_changes": [{
		"type": "azurerm_key_vault",
		"name": "good-kv",
		"change": {
			"actions": ["create"],
			"after": {
				"purge_protection_enabled": true,
				"enable_rbac_authorization": true,
			},
		},
	}]}
}

test_key_vault_no_purge_protection_noncompliant if {
	count(kms.deny) > 0 with input as {"resource_changes": [{
		"type": "azurerm_key_vault",
		"name": "bad-kv",
		"change": {
			"actions": ["create"],
			"after": {
				"purge_protection_enabled": false,
				"enable_rbac_authorization": true,
			},
		},
	}]}
}

test_key_vault_no_rbac_noncompliant if {
	count(kms.deny) > 0 with input as {"resource_changes": [{
		"type": "azurerm_key_vault",
		"name": "no-rbac-kv",
		"change": {
			"actions": ["create"],
			"after": {
				"purge_protection_enabled": true,
				"enable_rbac_authorization": false,
			},
		},
	}]}
}
