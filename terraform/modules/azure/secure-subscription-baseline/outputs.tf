output "log_analytics_workspace_id" {
  description = "Resource ID of the Log Analytics workspace receiving security logs"
  value       = azurerm_log_analytics_workspace.security.id
}

output "storage_account_id" {
  description = "Resource ID of the storage account used for security log archival"
  value       = azurerm_storage_account.security_logs.id
}
