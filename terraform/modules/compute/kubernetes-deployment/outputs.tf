output "deployment_name" {
  description = "Name of the Kubernetes deployment"
  value       = kubernetes_deployment.main.metadata[0].name
}

output "service_name" {
  description = "Name of the Kubernetes service"
  value       = kubernetes_service.main.metadata[0].name
}
