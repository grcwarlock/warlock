output "managed_identity_id" {
  description = "Resource ID of the user-assigned managed identity"
  value       = azurerm_user_assigned_identity.main.id
}

output "managed_identity_principal_id" {
  description = "Principal (object) ID of the managed identity — use for role assignments"
  value       = azurerm_user_assigned_identity.main.principal_id
}

output "managed_identity_client_id" {
  description = "Client ID of the managed identity — use in application configuration"
  value       = azurerm_user_assigned_identity.main.client_id
}

output "group_id" {
  description = "Resource ID of the Azure AD security group"
  value       = azuread_group.main.id
}

output "group_object_id" {
  description = "Object ID of the Azure AD security group — use for RBAC assignments"
  value       = azuread_group.main.object_id
}
