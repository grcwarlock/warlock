output "certificate_arn" {
  description = "ARN of the ACM certificate — use for ALB/CloudFront HTTPS listeners (SC-23)"
  value       = aws_acm_certificate.main.arn
}

output "certificate_domain_name" {
  description = "Primary domain name of the ACM certificate"
  value       = aws_acm_certificate.main.domain_name
}

output "certificate_status" {
  description = "Current status of the ACM certificate (PENDING_VALIDATION, ISSUED, etc.)"
  value       = aws_acm_certificate.main.status
}
