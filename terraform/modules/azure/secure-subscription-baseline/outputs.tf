output "log_analytics_workspace_id" {
  value = azurerm_log_analytics_workspace.security.id
}

output "storage_account_id" {
  value = azurerm_storage_account.security_logs.id
}
