output "instance_id" {
  description = "ID of the Huawei Cloud ECS instance"
  value       = huaweicloud_compute_instance.main.id
}

output "private_ip" {
  description = "Private IP address of the ECS instance"
  value       = huaweicloud_compute_instance.main.access_ip_v4
}
