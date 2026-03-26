output "instance_id" {
  description = "ID of the Alibaba Cloud Container Registry Enterprise Edition instance"
  value       = alicloud_cr_ee_instance.main.id
}

output "instance_name" {
  description = "Name of the Container Registry Enterprise Edition instance"
  value       = alicloud_cr_ee_instance.main.instance_name
}
