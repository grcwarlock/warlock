output "network_policy_name" {
  description = "Name of the default-deny network policy"
  value       = kubernetes_network_policy.default_deny.metadata[0].name
}
