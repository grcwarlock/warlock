locals {
  warlock_remediation = {
    risk_level    = "low"
    auto_approve  = false
    rollback_safe = true
    control_ids   = []
    connectors    = []
    limitations   = ["Vercel Terraform provider is community-maintained. For production, use the Vercel CLI or REST API."]
  }
}
