output "role_name" {
  description = "Name of the auditor ClusterRole"
  value       = kubernetes_cluster_role.auditor.metadata[0].name
}

output "binding_name" {
  description = "Name of the auditor ClusterRoleBinding"
  value       = kubernetes_cluster_role_binding.auditor.metadata[0].name
}
