package terraform.iam

import rego.v1

# AC-6 (Least Privilege): IAM policies must not use wildcard actions or resources.
# Detects both inline policies (aws_iam_role_policy) and managed policies (aws_iam_policy).

deny contains msg if {
	some resource in input.resource_changes
	resource.type in {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"}
	_is_create_or_update(resource)
	policy := json.unmarshal(resource.change.after.policy)
	some stmt in policy.Statement
	stmt.Effect == "Allow"
	stmt.Action == "*"
	msg := sprintf("IAM policy '%s' uses wildcard Action '*' — violates least privilege [AC-6]", [resource.name])
}

deny contains msg if {
	some resource in input.resource_changes
	resource.type in {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"}
	_is_create_or_update(resource)
	policy := json.unmarshal(resource.change.after.policy)
	some stmt in policy.Statement
	stmt.Effect == "Allow"
	stmt.Resource == "*"
	stmt.Action == "*"
	msg := sprintf("IAM policy '%s' allows Action '*' on Resource '*' — administrator-level access requires explicit approval [AC-6]", [resource.name])
}

# Detect Action arrays that include "*"
deny contains msg if {
	some resource in input.resource_changes
	resource.type in {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"}
	_is_create_or_update(resource)
	policy := json.unmarshal(resource.change.after.policy)
	some stmt in policy.Statement
	stmt.Effect == "Allow"
	is_array(stmt.Action)
	"*" in stmt.Action
	msg := sprintf("IAM policy '%s' includes wildcard '*' in Action array [AC-6]", [resource.name])
}

_is_create_or_update(resource) if {
	resource.change.actions[_] in {"create", "update"}
}
