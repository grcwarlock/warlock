locals {
  warlock_remediation = {
    risk_level    = "low"
    auto_approve  = false
    rollback_safe = true
    control_ids   = []
    connectors    = []
    limitations   = ["Netlify Terraform provider is community-maintained and may lag behind API features. Use Netlify CLI for production."]
  }
}
