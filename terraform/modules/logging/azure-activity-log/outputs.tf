output "diagnostic_setting_id" {
  description = "Resource ID of the Azure Monitor diagnostic setting"
  value       = azurerm_monitor_diagnostic_setting.subscription.id
}

output "log_analytics_workspace_id" {
  description = "Resource ID of the Log Analytics workspace (created or provided)"
  value       = local.workspace_id
}

output "log_analytics_workspace_name" {
  description = "Name of the Log Analytics workspace (null if an existing workspace was provided)"
  value       = local.create_workspace ? azurerm_log_analytics_workspace.main[0].name : null
}
