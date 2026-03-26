output "instance_id" {
  description = "ID of the virtual server instance"
  value       = ibm_is_instance.main.id
}

output "primary_ip" {
  description = "Primary IPv4 address of the instance"
  value       = ibm_is_instance.main.primary_network_interface[0].primary_ip[0].address
}
