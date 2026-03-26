output "instance_id" {
  description = "ID of the Alibaba Cloud ECS instance"
  value       = alicloud_instance.main.id
}

output "private_ip" {
  description = "Private IP address of the ECS instance"
  value       = alicloud_instance.main.private_ip
}
