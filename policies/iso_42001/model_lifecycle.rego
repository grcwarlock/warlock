package warlock.iso_42001.lifecycle

import rego.v1

# ISO 42001 AI Model Lifecycle Management
# A.6.2: AI system lifecycle processes

# A.6.2.3: AI system development — documented development process
deny_no_dev_process contains msg if {
	some system in input.normalized_data.ai_governance.ai_systems
	not system.development_process_documented
	msg := sprintf("A.6.2.3: AI system '%s' — development process not documented", [system.name])
}

# A.6.2.5: AI system verification and validation
deny_no_validation contains msg if {
	some system in input.normalized_data.ai_governance.ai_systems
	not system.validation_performed
	msg := sprintf("A.6.2.5: AI system '%s' — verification and validation not performed", [system.name])
}

# A.6.2.8: AI system deployment — controlled deployment process
deny_no_controlled_deployment contains msg if {
	some system in input.normalized_data.ai_governance.ai_systems
	system.in_production
	not system.controlled_deployment
	msg := sprintf("A.6.2.8: AI system '%s' in production without controlled deployment process", [system.name])
}

# A.6.2.10: AI system retirement — decommission process
deny_no_retirement_process contains msg if {
	some system in input.normalized_data.ai_governance.ai_systems
	system.deprecated
	not system.retirement_plan
	msg := sprintf("A.6.2.10: Deprecated AI system '%s' — no retirement plan", [system.name])
}

# A.6.2.12: AI system monitoring — performance monitoring in production
deny_no_production_monitoring contains msg if {
	some system in input.normalized_data.ai_governance.ai_systems
	system.in_production
	not system.performance_monitoring_enabled
	msg := sprintf("A.6.2.12: AI system '%s' in production without performance monitoring", [system.name])
}

default compliant := false

compliant if {
	count(deny_no_dev_process) == 0
	count(deny_no_validation) == 0
	count(deny_no_controlled_deployment) == 0
	count(deny_no_retirement_process) == 0
	count(deny_no_production_monitoring) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_dev_process],
		[f | some f in deny_no_validation],
	),
	array.concat(
		array.concat(
			[f | some f in deny_no_controlled_deployment],
			[f | some f in deny_no_retirement_process],
		),
		[f | some f in deny_no_production_monitoring],
	),
)

result := {
	"control_id": "A.6.2",
	"framework": "ISO 42001",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
