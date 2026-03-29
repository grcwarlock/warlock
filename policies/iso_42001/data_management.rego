package warlock.iso_42001.data_mgmt

import rego.v1

# ISO 42001 Data Management for AI Systems
# A.5.3, A.9: Data for AI systems

# A.5.3: AI system inventory — all AI systems registered
deny_no_ai_inventory contains msg if {
	not input.normalized_data.ai_governance.ai_inventory_maintained
	msg := "A.5.3: No AI system inventory maintained"
}

# A.9.2: Data quality requirements defined
deny_no_data_quality_requirements contains msg if {
	some system in input.normalized_data.ai_governance.ai_systems
	system.uses_training_data
	not system.data_quality_requirements_defined
	msg := sprintf("A.9.2: AI system '%s' — data quality requirements not defined", [system.name])
}

# A.9.3: Data provenance tracked
deny_no_data_provenance contains msg if {
	some system in input.normalized_data.ai_governance.ai_systems
	system.uses_training_data
	not system.data_provenance_tracked
	msg := sprintf("A.9.3: AI system '%s' — training data provenance not tracked", [system.name])
}

# A.9.4: Data preparation documented
deny_no_data_prep_docs contains msg if {
	some system in input.normalized_data.ai_governance.ai_systems
	system.uses_training_data
	not system.data_preparation_documented
	msg := sprintf("A.9.4: AI system '%s' — data preparation steps not documented", [system.name])
}

default compliant := false

compliant if {
	count(deny_no_ai_inventory) == 0
	count(deny_no_data_quality_requirements) == 0
	count(deny_no_data_provenance) == 0
	count(deny_no_data_prep_docs) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_ai_inventory],
		[f | some f in deny_no_data_quality_requirements],
	),
	array.concat(
		[f | some f in deny_no_data_provenance],
		[f | some f in deny_no_data_prep_docs],
	),
)

result := {
	"control_id": "A.9",
	"framework": "ISO 42001",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
