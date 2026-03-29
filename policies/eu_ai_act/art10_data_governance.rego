package warlock.eu_ai_act.art10

import rego.v1

# Art. 10: Data and Data Governance
# Training, validation, and testing data quality requirements

# 10.2: Data governance and management practices
deny_no_data_governance_practices contains msg if {
	some system in input.normalized_data.ai_systems
	system.risk_classification == "high"
	system.uses_training_data
	not system.data_governance_measures
	msg := sprintf("Art.10.2: High-risk AI system '%s' lacks data governance practices", [system.name])
}

# 10.2(a): Design choices for data collection
deny_no_data_collection_design contains msg if {
	some system in input.normalized_data.ai_systems
	system.risk_classification == "high"
	system.uses_training_data
	not system.data_collection_documented
	msg := sprintf("Art.10.2a: AI system '%s' — data collection design choices not documented", [system.name])
}

# 10.2(f): Bias examination and mitigation
deny_no_bias_examination contains msg if {
	some system in input.normalized_data.ai_systems
	system.risk_classification == "high"
	system.uses_training_data
	not system.bias_examination_performed
	msg := sprintf("Art.10.2f: AI system '%s' — training data not examined for bias", [system.name])
}

# 10.3: Training data representativeness
deny_not_representative contains msg if {
	some system in input.normalized_data.ai_systems
	system.risk_classification == "high"
	system.uses_training_data
	not system.data_representativeness_verified
	msg := sprintf("Art.10.3: AI system '%s' — training data representativeness not verified", [system.name])
}

# 10.4: Validation and testing datasets
deny_no_validation_data contains msg if {
	some system in input.normalized_data.ai_systems
	system.risk_classification == "high"
	system.uses_training_data
	not system.validation_dataset_defined
	msg := sprintf("Art.10.4: AI system '%s' — no separate validation and testing datasets", [system.name])
}

default compliant := false

compliant if {
	count(deny_no_data_governance_practices) == 0
	count(deny_no_data_collection_design) == 0
	count(deny_no_bias_examination) == 0
	count(deny_not_representative) == 0
	count(deny_no_validation_data) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_data_governance_practices],
		[f | some f in deny_no_data_collection_design],
	),
	array.concat(
		array.concat(
			[f | some f in deny_no_bias_examination],
			[f | some f in deny_not_representative],
		),
		[f | some f in deny_no_validation_data],
	),
)

result := {
	"control_id": "Art.10",
	"framework": "EU AI Act",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
