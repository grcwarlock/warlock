package iso_27001.a7.a7_12

import rego.v1

# A.7.12: Cabling Security
# Validates network encryption and secure connectivity configurations

deny_vpn_not_encrypted contains msg if {
	some vpn in input.normalized_data.vpn.connections
	vpn.state == "available"
	not vpn.encrypted
	msg := sprintf("A.7.12: VPN connection '%s' is not using encryption", [vpn.id])
}

deny_no_vpc_endpoints contains msg if {
	count(input.normalized_data.vpc_endpoints) == 0
	msg := "A.7.12: No VPC endpoints configured for private connectivity to AWS services"
}

deny_elb_no_tls contains msg if {
	some listener in input.normalized_data.elb.listeners
	listener.protocol == "HTTPS"
	not contains(listener.ssl_policy, "TLS-1-2")
	not contains(listener.ssl_policy, "TLS13")
	msg := sprintf("A.7.12: Load balancer listener '%s' uses weak TLS policy '%s'", [listener.arn, listener.ssl_policy])
}

deny_no_direct_connect_encryption contains msg if {
	some connection in input.normalized_data.directconnect.connections
	not connection.has_macsec
	msg := sprintf("A.7.12: Direct Connect '%s' does not have MACsec encryption enabled", [connection.id])
}

default compliant := false

compliant if {
	count(deny_vpn_not_encrypted) == 0
	count(deny_elb_no_tls) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_vpn_not_encrypted],
		[f | some f in deny_no_vpc_endpoints],
	),
	array.concat(
		[f | some f in deny_elb_no_tls],
		[f | some f in deny_no_direct_connect_encryption],
	),
)

result := {
	"control_id": "A.7.12",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
