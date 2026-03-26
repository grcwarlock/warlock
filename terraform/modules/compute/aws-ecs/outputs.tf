output "cluster_arn" {
  description = "ARN of the ECS cluster"
  value       = aws_ecs_cluster.main.arn
}

output "cluster_name" {
  description = "Name of the ECS cluster"
  value       = aws_ecs_cluster.main.name
}

output "log_group_arn" {
  description = "ARN of the CloudWatch log group for ECS container logs"
  value       = aws_cloudwatch_log_group.ecs.arn
}
