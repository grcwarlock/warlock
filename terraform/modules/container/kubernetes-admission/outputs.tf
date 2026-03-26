output "namespace" {
  description = "Namespace where the policy engine is deployed"
  value       = kubernetes_namespace.policy_system.metadata[0].name
}

output "release_name" {
  description = "Name of the Helm release for the admission controller"
  value       = helm_release.admission_controller.name
}
