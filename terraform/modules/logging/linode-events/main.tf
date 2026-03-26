###############################################################################
# Linode Events — Documentation-Only Stub
# Enforces: AU-2 (Auditable Events)
#
# Linode does not provide a native log forwarding Terraform resource.
# Events are available via the Linode API but cannot be forwarded natively.
# Use a syslog agent (rsyslog, Fluentd, Vector) on instances for log shipping.
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
}

resource "null_resource" "events_documentation" {
  triggers = {
    note = "Linode has no native log forwarding Terraform resource. Deploy a syslog agent on instances."
  }
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "logging/linode-events"
  resource_id    = "linode-events-manual"
  control_ids    = ["AU-2"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    log_forwarding    = "not-available"
    recommended_agent = "rsyslog/fluentd/vector"
    terraform_support = "false"
  }
}
