package warlock.iso_42001.responsible

import rego.v1

# ISO 42001 Responsible AI Controls
# A.2, A.4, A.10: Fairness, accountability, third-party management

# A.2.2: AI system objectives aligned with organizational values
deny_no_value_alignment contains msg if {
	some system in input.normalized_data.ai_governance.ai_systems
	not system.objectives_aligned
	msg := sprintf("A.2.2: AI system '%s' — objectives not aligned with organizational values", [system.name])
}

# A.4.3: Fairness assessment conducted
deny_no_fairness_assessment contains msg if {
	some system in input.normalized_data.ai_governance.ai_systems
	system.risk_level == "high"
	not system.fairness_assessment_conducted
	msg := sprintf("A.4.3: High-risk AI system '%s' — no fairness assessment conducted", [system.name])
}

# A.10.2: Third-party AI components assessed
deny_no_third_party_assessment contains msg if {
	some system in input.normalized_data.ai_governance.ai_systems
	system.uses_third_party_components
	not system.third_party_assessed
	msg := sprintf("A.10.2: AI system '%s' uses third-party components without assessment", [system.name])
}

# A.2.4: Roles and responsibilities for AI governance defined
deny_no_ai_roles contains msg if {
	not input.normalized_data.ai_governance.roles_defined
	msg := "A.2.4: AI governance roles and responsibilities not defined"
}

default compliant := false

compliant if {
	count(deny_no_value_alignment) == 0
	count(deny_no_fairness_assessment) == 0
	count(deny_no_third_party_assessment) == 0
	count(deny_no_ai_roles) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_value_alignment],
		[f | some f in deny_no_fairness_assessment],
	),
	array.concat(
		[f | some f in deny_no_third_party_assessment],
		[f | some f in deny_no_ai_roles],
	),
)

result := {
	"control_id": "A.2/A.4/A.10",
	"framework": "ISO 42001",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
