output "job_id" {
  description = "ID of the Cloudflare Logpush job"
  value       = cloudflare_logpush_job.main.id
}
