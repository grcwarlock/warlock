package iso_27001.a5.a5_22

import rego.v1

# A.5.22: Monitoring, Review and Change Management of Supplier Services
# Validates supplier service monitoring and review processes

deny_no_health_monitoring contains msg if {
	not input.normalized_data.health.monitoring_active
	msg := "A.5.22: AWS Health monitoring is not active for supplier service health tracking"
}

deny_no_health_event_notifications contains msg if {
	not input.normalized_data.eventbridge.health_alert_rule_exists
	msg := "A.5.22: No EventBridge rule configured for AWS Health event notifications"
}

deny_no_trusted_advisor contains msg if {
	not input.normalized_data.support.trusted_advisor_enabled
	msg := "A.5.22: Trusted Advisor is not enabled for service review recommendations"
}

deny_no_supplier_review_process contains msg if {
	not input.normalized_data.policies.supplier_review_process_documented
	msg := "A.5.22: No documented process for periodic supplier service review"
}

default compliant := false

compliant if {
	count(deny_no_health_monitoring) == 0
	count(deny_no_health_event_notifications) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_health_monitoring],
		[f | some f in deny_no_health_event_notifications],
	),
	array.concat(
		[f | some f in deny_no_trusted_advisor],
		[f | some f in deny_no_supplier_review_process],
	),
)

result := {
	"control_id": "A.5.22",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
