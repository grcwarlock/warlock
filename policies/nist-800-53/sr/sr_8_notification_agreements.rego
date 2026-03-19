package nist.sr.sr_8

import rego.v1

# SR-8: Notification Agreements

deny_no_notification_agreements contains msg if {
	not input.normalized_data.supplier_notification_agreements
	msg := "SR-8: No notification agreements established with suppliers"
}

deny_supplier_no_agreement contains msg if {
	some supplier in input.normalized_data.suppliers
	supplier.is_critical
	not supplier.notification_agreement_signed
	msg := sprintf("SR-8: No notification agreement signed with critical supplier '%s'", [supplier.name])
}

deny_agreement_no_breach_notification contains msg if {
	some supplier in input.normalized_data.suppliers
	supplier.notification_agreement_signed
	not supplier.breach_notification_included
	msg := sprintf("SR-8: Notification agreement with '%s' does not include breach notification requirements", [supplier.name])
}

deny_agreement_no_vulnerability_notification contains msg if {
	some supplier in input.normalized_data.suppliers
	supplier.notification_agreement_signed
	not supplier.vulnerability_notification_included
	msg := sprintf("SR-8: Notification agreement with '%s' does not include vulnerability notification requirements", [supplier.name])
}

deny_agreements_outdated contains msg if {
	na := input.normalized_data.supplier_notification_agreements
	na.last_review_days > 365
	msg := sprintf("SR-8: Notification agreements have not been reviewed in %d days", [na.last_review_days])
}

default compliant := false

compliant if {
	count(deny_no_notification_agreements) == 0
	count(deny_supplier_no_agreement) == 0
	count(deny_agreement_no_breach_notification) == 0
	count(deny_agreement_no_vulnerability_notification) == 0
	count(deny_agreements_outdated) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_notification_agreements],
		[f | some f in deny_supplier_no_agreement],
	),
	array.concat(
		[f | some f in deny_agreement_no_breach_notification],
		array.concat(
			[f | some f in deny_agreement_no_vulnerability_notification],
			[f | some f in deny_agreements_outdated],
		),
	),
)

result := {
	"control_id": "SR-8",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
