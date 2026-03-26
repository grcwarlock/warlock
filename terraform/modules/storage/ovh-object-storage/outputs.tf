output "container_name" {
  description = "Name of the OpenStack Swift object storage container"
  value       = openstack_objectstorage_container_v1.main.name
}
