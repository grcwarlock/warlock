package terraform.iam_test

import rego.v1

import data.terraform.iam

_make_policy_resource(name, actions, resource_val) := {"resource_changes": [{
	"type": "aws_iam_policy",
	"name": name,
	"change": {
		"actions": ["create"],
		"after": {"policy": json.marshal({
			"Version": "2012-10-17",
			"Statement": [{"Effect": "Allow", "Action": actions, "Resource": resource_val}],
		})},
	},
}]}

test_iam_scoped_policy_compliant if {
	count(iam.deny) == 0 with input as _make_policy_resource(
		"good-policy",
		["s3:GetObject", "s3:PutObject"],
		"arn:aws:s3:::my-bucket/*",
	)
}

test_iam_wildcard_action_string_noncompliant if {
	count(iam.deny) > 0 with input as {"resource_changes": [{
		"type": "aws_iam_policy",
		"name": "bad-wildcard-policy",
		"change": {
			"actions": ["create"],
			"after": {"policy": json.marshal({
				"Version": "2012-10-17",
				"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
			})},
		},
	}]}
}

test_iam_wildcard_in_action_array_noncompliant if {
	count(iam.deny) > 0 with input as {"resource_changes": [{
		"type": "aws_iam_role_policy",
		"name": "wildcard-array-policy",
		"change": {
			"actions": ["create"],
			"after": {"policy": json.marshal({
				"Version": "2012-10-17",
				"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "*"], "Resource": "*"}],
			})},
		},
	}]}
}

test_iam_deny_effect_with_wildcard_compliant if {
	# Deny statements with wildcards are acceptable (e.g. DenyAll)
	count(iam.deny) == 0 with input as {"resource_changes": [{
		"type": "aws_iam_policy",
		"name": "deny-all-policy",
		"change": {
			"actions": ["create"],
			"after": {"policy": json.marshal({
				"Version": "2012-10-17",
				"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
			})},
		},
	}]}
}
