###############################################################################
# Warlock Self-Registration — Shared Submodule
# Posts evidence to the Warlock API when a module is applied.
# Include in every domain module via: module "warlock_registration" { ... }
###############################################################################

resource "terraform_data" "warlock_evidence" {
  count = var.enabled ? 1 : 0

  triggers_replace = [var.resource_id]

  provisioner "local-exec" {
    environment = {
      WARLOCK_API_ENDPOINT = var.api_endpoint
      WARLOCK_API_TOKEN    = var.api_token
    }
    command = <<-EOT
      curl -sf -X POST "$WARLOCK_API_ENDPOINT/api/v1/evidence" \
        -H "Authorization: Bearer $WARLOCK_API_TOKEN" \
        -H "Content-Type: application/json" \
        -d '${jsonencode({
    module         = var.module_name
    resource_id    = var.resource_id
    control_ids    = var.control_ids
    attributes     = var.attributes
    action         = var.remediation_id != null ? "remediate" : "provision"
    remediation_id = var.remediation_id
})}' || true
    EOT
}
}
