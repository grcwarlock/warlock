package terraform.cloudtrail

import rego.v1

# AU-2: CloudTrail must be multi-region to capture all API activity.
# AU-9: Log file validation must be enabled to ensure integrity.

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_cloudtrail"
	_is_create_or_update(resource)
	not resource.change.after.is_multi_region_trail
	msg := sprintf("CloudTrail '%s' must be a multi-region trail (is_multi_region_trail = true) [AU-2]", [resource.name])
}

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_cloudtrail"
	_is_create_or_update(resource)
	not resource.change.after.enable_log_file_validation
	msg := sprintf("CloudTrail '%s' must have log file validation enabled [AU-9]", [resource.name])
}

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_cloudtrail"
	_is_create_or_update(resource)
	not resource.change.after.include_global_service_events
	msg := sprintf("CloudTrail '%s' must include global service events [AU-2]", [resource.name])
}

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_cloudtrail"
	_is_create_or_update(resource)
	not resource.change.after.enable_logging
	msg := sprintf("CloudTrail '%s' logging must be enabled [AU-2]", [resource.name])
}

_is_create_or_update(resource) if {
	resource.change.actions[_] in {"create", "update"}
}
