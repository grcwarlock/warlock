output "instance_id" {
  description = "OCID of the compute instance"
  value       = oci_core_instance.main.id
}

output "private_ip" {
  description = "Private IP address of the instance primary VNIC"
  value       = oci_core_instance.main.private_ip
}
