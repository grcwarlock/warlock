output "namespace_names" {
  description = "Names of the namespaces with Pod Security Standards applied"
  value       = [for ns in kubernetes_namespace.pss : ns.metadata[0].name]
}
