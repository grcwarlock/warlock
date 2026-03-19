package iso_27001.a8.a8_32

import rego.v1

# A.8.32: Change Management
# Validates change management processes and approval workflows

deny_no_iac contains msg if {
	count(input.normalized_data.cloudformation.stacks) == 0
	msg := "A.8.32: No CloudFormation stacks — infrastructure is not managed as code"
}

deny_stack_drift contains msg if {
	some stack in input.normalized_data.cloudformation.stacks
	stack.drift_status == "DRIFTED"
	msg := sprintf("A.8.32: CloudFormation stack '%s' has drifted from its template — unauthorized changes detected", [stack.name])
}

deny_no_drift_detection_rule contains msg if {
	not input.normalized_data.config.stack_drift_rule_exists
	msg := "A.8.32: No Config rule monitors for CloudFormation stack drift"
}

deny_pipeline_no_approval contains msg if {
	some pipeline in input.normalized_data.pipelines
	not pipeline.has_approval_stage
	msg := sprintf("A.8.32: Pipeline '%s' has no manual approval stage for change control", [pipeline.name])
}

deny_no_config_change_tracking contains msg if {
	not input.normalized_data.config.recorder_enabled
	msg := "A.8.32: AWS Config is not enabled — configuration changes are not tracked"
}

default compliant := false

compliant if {
	count(deny_no_iac) == 0
	count(deny_stack_drift) == 0
	count(deny_no_config_change_tracking) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_iac],
		[f | some f in deny_stack_drift],
	),
	array.concat(
		[f | some f in deny_no_drift_detection_rule],
		array.concat(
			[f | some f in deny_pipeline_no_approval],
			[f | some f in deny_no_config_change_tracking],
		),
	),
)

result := {
	"control_id": "A.8.32",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
