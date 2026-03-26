locals {
  warlock_remediation = {
    risk_level    = "low"
    auto_approve  = false
    rollback_safe = true
    control_ids   = []
    connectors    = []
    limitations   = ["Supabase does not have an official Terraform provider. Projects must be managed via the Supabase Dashboard or Management API."]
  }
}
