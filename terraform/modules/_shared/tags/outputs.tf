output "merged" {
  description = "Merged tag map: Warlock standard + user-supplied tags"
  value       = merge(local.standard, var.extra_tags)
}

output "merged_labels" {
  description = "Same as merged but with lowercase keys and underscores (for GCP/Alibaba labels)"
  value = {
    for k, v in merge(local.standard, var.extra_tags) :
    lower(replace(k, "/[^a-z0-9_-]/", "_")) => lower(v)
  }
}
