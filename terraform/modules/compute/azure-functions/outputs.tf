output "function_app_id" {
  description = "Resource ID of the Azure Linux Function App"
  value       = azurerm_linux_function_app.main.id
}

output "function_app_default_hostname" {
  description = "Default hostname of the Function App"
  value       = azurerm_linux_function_app.main.default_hostname
}

output "app_insights_instrumentation_key" {
  description = "Instrumentation key for Application Insights (AU-2)"
  value       = azurerm_application_insights.main.instrumentation_key
  sensitive   = true
}
