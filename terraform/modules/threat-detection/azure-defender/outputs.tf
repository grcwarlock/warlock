output "defender_pricing_ids" {
  description = "Map of resource type to Defender for Cloud pricing resource IDs"
  value       = { for k, v in azurerm_security_center_subscription_pricing.defender : k => v.id }
}

output "security_contact_id" {
  description = "Resource ID of the Defender for Cloud security contact"
  value       = azurerm_security_center_contact.main.id
}
