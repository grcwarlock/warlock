output "bucket_name" {
  description = "Name of the Cloudflare R2 bucket"
  value       = cloudflare_r2_bucket.main.name
}

output "bucket_id" {
  description = "ID of the Cloudflare R2 bucket"
  value       = cloudflare_r2_bucket.main.id
}
