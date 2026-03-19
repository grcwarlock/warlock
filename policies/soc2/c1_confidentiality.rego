package soc2.c1

import rego.v1

# SOC 2 C1: Confidentiality
# Data classification, encryption, DLP, retention policies

deny_no_data_classification contains msg if {
	not input.normalized_data.confidentiality.data_classification_policy_exists
	msg := "C1.1: No data classification policy — confidential information not identified and categorized"
}

deny_no_encryption_at_rest contains msg if {
	input.provider == "aws"
	some resource in input.normalized_data.confidentiality.storage_resources
	not resource.encryption_at_rest_enabled
	msg := sprintf("C1.1: Resource '%s' lacks encryption at rest — confidential data not protected in storage", [resource.name])
}

deny_no_encryption_in_transit contains msg if {
	input.provider == "aws"
	some resource in input.normalized_data.confidentiality.endpoints
	not resource.tls_enabled
	msg := sprintf("C1.1: Endpoint '%s' does not enforce TLS — confidential data not protected in transit", [resource.name])
}

deny_no_dlp_rules contains msg if {
	not input.normalized_data.confidentiality.dlp_rules_configured
	msg := "C1.1: No DLP rules configured — unauthorized disclosure of confidential information not prevented"
}

deny_no_retention_policy contains msg if {
	not input.normalized_data.confidentiality.retention_policy_exists
	msg := "C1.2: No data retention policy — lifecycle of confidential information not governed"
}

deny_no_disposal_procedures contains msg if {
	not input.normalized_data.confidentiality.data_disposal_procedures_exist
	msg := "C1.2: No data disposal procedures — confidential information not securely destroyed when no longer needed"
}

deny_no_access_restrictions contains msg if {
	some resource in input.normalized_data.confidentiality.storage_resources
	resource.classification == "confidential"
	resource.public_access_enabled
	msg := sprintf("C1.1: Confidential resource '%s' has public access enabled", [resource.name])
}

default compliant := false

compliant if {
	count(deny_no_data_classification) == 0
	count(deny_no_encryption_at_rest) == 0
	count(deny_no_encryption_in_transit) == 0
	count(deny_no_dlp_rules) == 0
	count(deny_no_retention_policy) == 0
	count(deny_no_disposal_procedures) == 0
	count(deny_no_access_restrictions) == 0
}

findings := array.concat(
	array.concat(
		array.concat(
			[f | some f in deny_no_data_classification],
			[f | some f in deny_no_encryption_at_rest],
		),
		array.concat(
			[f | some f in deny_no_encryption_in_transit],
			[f | some f in deny_no_dlp_rules],
		),
	),
	array.concat(
		[f | some f in deny_no_retention_policy],
		array.concat(
			[f | some f in deny_no_disposal_procedures],
			[f | some f in deny_no_access_restrictions],
		),
	),
)

result := {
	"control_id": "C1",
	"framework": "SOC 2",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
