output "server_id" {
  description = "Resource ID of the Azure SQL Server"
  value       = azurerm_mssql_server.main.id
}

output "server_fqdn" {
  description = "Fully qualified domain name of the Azure SQL Server"
  value       = azurerm_mssql_server.main.fully_qualified_domain_name
}

output "database_id" {
  description = "Resource ID of the Azure SQL Database"
  value       = azurerm_mssql_database.main.id
}
