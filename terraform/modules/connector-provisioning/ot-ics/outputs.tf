output "firewall_rule_ids" {
  description = "List of security group and NACL IDs created for OT boundary enforcement"
  value = compact([
    aws_security_group.warlock_ot_access.id,
    aws_security_group.ot_warlock_ingress.id,
    var.create_nacl ? aws_network_acl.ot_boundary[0].id : null,
  ])
}

output "warlock_access_sg_id" {
  description = "Security group ID for Warlock-to-OT egress rules"
  value       = aws_security_group.warlock_ot_access.id
}

output "ot_ingress_sg_id" {
  description = "Security group ID for OT network ingress from Warlock"
  value       = aws_security_group.ot_warlock_ingress.id
}

output "flow_log_group_name" {
  description = "CloudWatch log group for VPC flow logs at the OT boundary"
  value       = aws_cloudwatch_log_group.ot_flow_logs.name
}
