output "vnet_id" {
  description = "Resource ID of the Azure Virtual Network"
  value       = azurerm_virtual_network.main.id
}

output "vnet_name" {
  description = "Name of the Azure Virtual Network"
  value       = azurerm_virtual_network.main.name
}

output "public_subnet_ids" {
  description = "Map of public subnet keys to their resource IDs"
  value       = { for k, v in azurerm_subnet.public : k => v.id }
}

output "private_subnet_ids" {
  description = "Map of private subnet keys to their resource IDs"
  value       = { for k, v in azurerm_subnet.private : k => v.id }
}

output "nsg_id" {
  description = "Resource ID of the Network Security Group"
  value       = azurerm_network_security_group.main.id
}
