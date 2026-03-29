package warlock.eu_ai_act.art14

import rego.v1

# Art. 14: Human Oversight
# High-risk AI systems designed with appropriate human-machine interface tools

# 14.1: Human oversight measures built into AI system
deny_no_oversight_measures contains msg if {
	some system in input.normalized_data.ai_systems
	system.risk_classification == "high"
	not system.human_oversight_mechanism
	msg := sprintf("Art.14.1: High-risk AI system '%s' lacks human oversight measures", [system.name])
}

# 14.2: Oversight aimed at preventing or minimizing risks
deny_no_risk_awareness contains msg if {
	some system in input.normalized_data.ai_systems
	system.risk_classification == "high"
	not system.oversight_risk_awareness
	msg := sprintf("Art.14.2: AI system '%s' — oversight does not address risk prevention", [system.name])
}

# 14.4(a): Ability to understand AI system capabilities and limitations
deny_no_capability_understanding contains msg if {
	some system in input.normalized_data.ai_systems
	system.risk_classification == "high"
	not system.capabilities_documented
	msg := sprintf("Art.14.4a: AI system '%s' — capabilities and limitations not documented for overseers", [system.name])
}

# 14.4(d): Ability to decide not to use or to override AI output
deny_no_override_capability contains msg if {
	some system in input.normalized_data.ai_systems
	system.risk_classification == "high"
	not system.human_override_enabled
	msg := sprintf("Art.14.4d: AI system '%s' — no ability to override or disregard AI output", [system.name])
}

# 14.4(e): Ability to intervene or interrupt system operation
deny_no_interrupt_capability contains msg if {
	some system in input.normalized_data.ai_systems
	system.risk_classification == "high"
	not system.interrupt_mechanism
	msg := sprintf("Art.14.4e: AI system '%s' — no mechanism to interrupt system operation", [system.name])
}

default compliant := false

compliant if {
	count(deny_no_oversight_measures) == 0
	count(deny_no_risk_awareness) == 0
	count(deny_no_capability_understanding) == 0
	count(deny_no_override_capability) == 0
	count(deny_no_interrupt_capability) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_oversight_measures],
		[f | some f in deny_no_risk_awareness],
	),
	array.concat(
		array.concat(
			[f | some f in deny_no_capability_understanding],
			[f | some f in deny_no_override_capability],
		),
		[f | some f in deny_no_interrupt_capability],
	),
)

result := {
	"control_id": "Art.14",
	"framework": "EU AI Act",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
