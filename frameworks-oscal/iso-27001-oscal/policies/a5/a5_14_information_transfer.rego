package iso_27001.a5.a5_14

import rego.v1

# A.5.14: Information Transfer
# Validates encryption in transit is enforced for all data transfers

deny_bucket_no_ssl contains msg if {
	some bucket in input.normalized_data.s3.buckets
	not bucket.ssl_enforced
	msg := sprintf("A.5.14: S3 bucket '%s' does not enforce SSL/TLS for data transfer", [bucket.name])
}

deny_elb_weak_tls contains msg if {
	some listener in input.normalized_data.elb.listeners
	listener.protocol == "HTTPS"
	not is_tls_1_2_or_higher(listener.ssl_policy)
	msg := sprintf("A.5.14: Load balancer listener '%s' uses weak TLS policy '%s' — minimum TLS 1.2 required", [listener.arn, listener.ssl_policy])
}

deny_no_vpc_flow_logs contains msg if {
	some vpc in input.normalized_data.vpcs
	not vpc.flow_logs_enabled
	msg := sprintf("A.5.14: VPC '%s' has no flow logs to monitor data transfers", [vpc.id])
}

deny_http_listeners contains msg if {
	some listener in input.normalized_data.elb.listeners
	listener.protocol == "HTTP"
	listener.port != 80
	msg := sprintf("A.5.14: Load balancer has unencrypted HTTP listener on port %d", [listener.port])
}

is_tls_1_2_or_higher(policy) if {
	contains(policy, "TLS-1-2")
}

is_tls_1_2_or_higher(policy) if {
	contains(policy, "TLS13")
}

default compliant := false

compliant if {
	count(deny_bucket_no_ssl) == 0
	count(deny_elb_weak_tls) == 0
	count(deny_no_vpc_flow_logs) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_bucket_no_ssl],
		[f | some f in deny_elb_weak_tls],
	),
	array.concat(
		[f | some f in deny_no_vpc_flow_logs],
		[f | some f in deny_http_listeners],
	),
)

result := {
	"control_id": "A.5.14",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
