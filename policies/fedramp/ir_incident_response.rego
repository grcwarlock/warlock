package warlock.fedramp.ir

import rego.v1

# FedRAMP Incident Response Requirements

# IR-2: Incident response training
deny_no_ir_training contains msg if {
	not input.normalized_data.incident_response.training_conducted
	msg := "IR-2: Incident response training not conducted — FedRAMP requires annual training"
}

# IR-4: Incident handling — automated mechanisms
deny_no_incident_handling contains msg if {
	not input.normalized_data.incident_response.automated_handling
	msg := "IR-4: No automated incident handling process — manual-only response"
}

# IR-5: Incident monitoring — tracking and documenting incidents
deny_no_incident_tracking contains msg if {
	not input.normalized_data.incident_response.incident_tracking_enabled
	msg := "IR-5: No incident tracking system — cannot document security incidents"
}

# IR-6: Incident reporting — reporting to US-CERT within required timeframe
deny_no_uscert_reporting contains msg if {
	not input.normalized_data.incident_response.uscert_reporting_configured
	msg := "IR-6: US-CERT incident reporting not configured — FedRAMP requires 1-hour reporting for Category 1"
}

# IR-8: Incident response plan — documented and tested
deny_no_ir_plan contains msg if {
	not input.normalized_data.incident_response.plan_documented
	msg := "IR-8: No documented incident response plan"
}

default compliant := false

compliant if {
	count(deny_no_ir_training) == 0
	count(deny_no_incident_handling) == 0
	count(deny_no_incident_tracking) == 0
	count(deny_no_uscert_reporting) == 0
	count(deny_no_ir_plan) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_ir_training],
		[f | some f in deny_no_incident_handling],
	),
	array.concat(
		array.concat(
			[f | some f in deny_no_incident_tracking],
			[f | some f in deny_no_uscert_reporting],
		),
		[f | some f in deny_no_ir_plan],
	),
)

result := {
	"control_id": "IR",
	"framework": "FedRAMP",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
