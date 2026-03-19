package nist.cp.cp_6

import rego.v1

# CP-6: Alternate Storage Site
# Validates alternate storage site is configured for backup information

deny_no_alternate_storage contains msg if {
	not input.normalized_data.alternate_storage
	msg := "CP-6: No alternate storage site configured"
}

deny_no_cross_region_replication contains msg if {
	input.provider == "aws"
	some bucket in input.normalized_data.storage_buckets
	bucket.contains_backups
	not bucket.cross_region_replication_enabled
	msg := sprintf("CP-6: S3 bucket '%s' containing backups does not have cross-region replication enabled", [bucket.name])
}

deny_no_geo_redundant_storage contains msg if {
	input.provider == "azure"
	some account in input.normalized_data.storage_accounts
	account.contains_backups
	not account.geo_redundant
	msg := sprintf("CP-6: Azure storage account '%s' containing backups is not geo-redundant", [account.name])
}

deny_same_region_storage contains msg if {
	input.normalized_data.alternate_storage
	input.normalized_data.alternate_storage.primary_region == input.normalized_data.alternate_storage.alternate_region
	msg := "CP-6: Alternate storage site is in the same region as primary — must be geographically separated"
}

deny_no_storage_agreement contains msg if {
	input.normalized_data.alternate_storage
	not input.normalized_data.alternate_storage.agreement_documented
	msg := "CP-6: Alternate storage site agreement is not documented"
}

deny_storage_not_encrypted contains msg if {
	input.normalized_data.alternate_storage
	not input.normalized_data.alternate_storage.encryption_enabled
	msg := "CP-6: Backup data at alternate storage site is not encrypted"
}

default compliant := false

compliant if {
	count(deny_no_alternate_storage) == 0
	count(deny_no_cross_region_replication) == 0
	count(deny_no_geo_redundant_storage) == 0
	count(deny_same_region_storage) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_alternate_storage],
		[f | some f in deny_no_cross_region_replication],
	),
	array.concat(
		[f | some f in deny_no_geo_redundant_storage],
		array.concat(
			[f | some f in deny_same_region_storage],
			array.concat(
				[f | some f in deny_no_storage_agreement],
				[f | some f in deny_storage_not_encrypted],
			),
		),
	),
)

result := {
	"control_id": "CP-6",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
