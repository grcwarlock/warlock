output "ruleset_id" {
  description = "ID of the Cloudflare WAF managed ruleset"
  value       = cloudflare_ruleset.waf_managed.id
}
