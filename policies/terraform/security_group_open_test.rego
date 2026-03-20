package terraform.sg_test

import rego.v1

import data.terraform.sg

test_sg_rule_restricted_compliant if {
	count(sg.deny) == 0 with input as {"resource_changes": [{
		"type": "aws_security_group_rule",
		"name": "restricted-ssh",
		"change": {
			"actions": ["create"],
			"after": {"type": "ingress", "from_port": 22, "to_port": 22, "cidr_blocks": ["10.0.0.0/8"]},
		},
	}]}
}

test_sg_rule_ssh_open_noncompliant if {
	count(sg.deny) > 0 with input as {"resource_changes": [{
		"type": "aws_security_group_rule",
		"name": "open-ssh",
		"change": {
			"actions": ["create"],
			"after": {"type": "ingress", "from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]},
		},
	}]}
}

test_sg_rule_rdp_open_noncompliant if {
	count(sg.deny) > 0 with input as {"resource_changes": [{
		"type": "aws_security_group_rule",
		"name": "open-rdp",
		"change": {
			"actions": ["create"],
			"after": {"type": "ingress", "from_port": 3389, "to_port": 3389, "cidr_blocks": ["0.0.0.0/0"]},
		},
	}]}
}

test_sg_rule_https_open_compliant if {
	# HTTPS 443 from 0.0.0.0/0 is allowed (public web)
	count(sg.deny) == 0 with input as {"resource_changes": [{
		"type": "aws_security_group_rule",
		"name": "public-https",
		"change": {
			"actions": ["create"],
			"after": {"type": "ingress", "from_port": 443, "to_port": 443, "cidr_blocks": ["0.0.0.0/0"]},
		},
	}]}
}

test_sg_rule_http_open_compliant if {
	# HTTP 80 from 0.0.0.0/0 is allowed (public web, to redirect to HTTPS)
	count(sg.deny) == 0 with input as {"resource_changes": [{
		"type": "aws_security_group_rule",
		"name": "public-http",
		"change": {
			"actions": ["create"],
			"after": {"type": "ingress", "from_port": 80, "to_port": 80, "cidr_blocks": ["0.0.0.0/0"]},
		},
	}]}
}

test_sg_rule_ipv6_ssh_open_noncompliant if {
	count(sg.deny) > 0 with input as {"resource_changes": [{
		"type": "aws_security_group_rule",
		"name": "ipv6-open-ssh",
		"change": {
			"actions": ["create"],
			"after": {"type": "ingress", "from_port": 22, "to_port": 22, "cidr_blocks": ["::/0"]},
		},
	}]}
}
