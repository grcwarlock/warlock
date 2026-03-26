output "target_id" {
  description = "OCID of the Cloud Guard target"
  value       = oci_cloud_guard_target.main.id
}

output "detector_recipe_id" {
  description = "OCID of the cloned Cloud Guard detector recipe"
  value       = oci_cloud_guard_detector_recipe.main.id
}
