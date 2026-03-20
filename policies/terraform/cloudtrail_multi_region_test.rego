package terraform.cloudtrail_test

import rego.v1

import data.terraform.cloudtrail

test_cloudtrail_fully_compliant if {
	count(cloudtrail.deny) == 0 with input as {"resource_changes": [{
		"type": "aws_cloudtrail",
		"name": "good-trail",
		"change": {
			"actions": ["create"],
			"after": {
				"is_multi_region_trail": true,
				"enable_log_file_validation": true,
				"include_global_service_events": true,
				"enable_logging": true,
			},
		},
	}]}
}

test_cloudtrail_not_multi_region_noncompliant if {
	count(cloudtrail.deny) > 0 with input as {"resource_changes": [{
		"type": "aws_cloudtrail",
		"name": "single-region-trail",
		"change": {
			"actions": ["create"],
			"after": {
				"is_multi_region_trail": false,
				"enable_log_file_validation": true,
				"include_global_service_events": true,
				"enable_logging": true,
			},
		},
	}]}
}

test_cloudtrail_no_log_validation_noncompliant if {
	count(cloudtrail.deny) > 0 with input as {"resource_changes": [{
		"type": "aws_cloudtrail",
		"name": "no-validation-trail",
		"change": {
			"actions": ["create"],
			"after": {
				"is_multi_region_trail": true,
				"enable_log_file_validation": false,
				"include_global_service_events": true,
				"enable_logging": true,
			},
		},
	}]}
}

test_cloudtrail_logging_disabled_noncompliant if {
	count(cloudtrail.deny) > 0 with input as {"resource_changes": [{
		"type": "aws_cloudtrail",
		"name": "disabled-trail",
		"change": {
			"actions": ["create"],
			"after": {
				"is_multi_region_trail": true,
				"enable_log_file_validation": true,
				"include_global_service_events": true,
				"enable_logging": false,
			},
		},
	}]}
}
