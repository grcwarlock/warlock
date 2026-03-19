package iso_27001.a8.a8_21

import rego.v1

# A.8.21: Security of Network Services
# Validates network service security configurations

deny_no_https_listeners contains msg if {
	some lb in input.normalized_data.elb.load_balancers
	not lb.has_https_listener
	msg := sprintf("A.8.21: Load balancer '%s' has no HTTPS listener configured", [lb.name])
}

deny_no_waf contains msg if {
	count(input.normalized_data.waf.web_acls) == 0
	msg := "A.8.21: No WAF web ACLs configured for application protection"
}

deny_cloudfront_no_tls contains msg if {
	some dist in input.normalized_data.cloudfront.distributions
	dist.viewer_protocol_policy != "https-only"
	dist.viewer_protocol_policy != "redirect-to-https"
	msg := sprintf("A.8.21: CloudFront distribution '%s' allows non-HTTPS viewer access", [dist.id])
}

deny_api_no_auth contains msg if {
	some api in input.normalized_data.apigateway.apis
	not api.authentication_configured
	msg := sprintf("A.8.21: API Gateway '%s' has no authentication configured", [api.name])
}

default compliant := false

compliant if {
	count(deny_no_https_listeners) == 0
	count(deny_no_waf) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_https_listeners],
		[f | some f in deny_no_waf],
	),
	array.concat(
		[f | some f in deny_cloudfront_no_tls],
		[f | some f in deny_api_no_auth],
	),
)

result := {
	"control_id": "A.8.21",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
