output "automation_account_id" {
  description = "Resource ID of the Azure Automation account for drift detection"
  value       = azurerm_automation_account.drift.id
}

output "runbook_name" {
  description = "Name of the drift detection runbook"
  value       = azurerm_automation_runbook.drift.name
}

output "schedule_name" {
  description = "Name of the recurring drift detection schedule"
  value       = azurerm_automation_schedule.drift.name
}
