output "vm_id" {
  description = "Resource ID of the Azure Linux VM"
  value       = azurerm_linux_virtual_machine.main.id
}

output "vm_private_ip" {
  description = "Private IP address of the VM"
  value       = azurerm_linux_virtual_machine.main.private_ip_address
}

output "vm_identity_principal_id" {
  description = "Principal ID of the VM system-assigned managed identity (IA-2)"
  value       = azurerm_linux_virtual_machine.main.identity[0].principal_id
}
