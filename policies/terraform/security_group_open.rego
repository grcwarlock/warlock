package terraform.sg

import rego.v1

# SC-7 (Boundary Protection): Security groups must not expose services to 0.0.0.0/0 or ::/0.
# Covers aws_security_group inline rules and aws_security_group_rule resources.

_open_cidrs := {"0.0.0.0/0", "::/0"}

# Inline ingress rules on aws_security_group
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_security_group"
	_is_create_or_update(resource)
	some rule in resource.change.after.ingress
	rule.cidr_blocks[_] in _open_cidrs
	not _is_allowed_public_port(rule.from_port, rule.to_port)
	msg := sprintf("Security group '%s' has unrestricted ingress (0.0.0.0/0 or ::/0) on ports %d-%d [SC-7]", [resource.name, rule.from_port, rule.to_port])
}

# Standalone aws_security_group_rule — ingress
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_security_group_rule"
	_is_create_or_update(resource)
	resource.change.after.type == "ingress"
	resource.change.after.cidr_blocks[_] in _open_cidrs
	not _is_allowed_public_port(resource.change.after.from_port, resource.change.after.to_port)
	msg := sprintf("Security group rule '%s' allows unrestricted ingress on ports %d-%d [SC-7]", [resource.name, resource.change.after.from_port, resource.change.after.to_port])
}

# ssh (22) explicitly — belt-and-suspenders
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_security_group_rule"
	_is_create_or_update(resource)
	resource.change.after.type == "ingress"
	resource.change.after.from_port <= 22
	resource.change.after.to_port >= 22
	resource.change.after.cidr_blocks[_] in _open_cidrs
	msg := sprintf("Security group rule '%s' allows SSH (port 22) from 0.0.0.0/0 [SC-7]", [resource.name])
}

# rdp (3389) explicitly
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_security_group_rule"
	_is_create_or_update(resource)
	resource.change.after.type == "ingress"
	resource.change.after.from_port <= 3389
	resource.change.after.to_port >= 3389
	resource.change.after.cidr_blocks[_] in _open_cidrs
	msg := sprintf("Security group rule '%s' allows RDP (port 3389) from 0.0.0.0/0 [SC-7]", [resource.name])
}

# Ports that are legitimately public (80/443 for web workloads)
_is_allowed_public_port(from, to) if {
	from <= 80
	to >= 80
}

_is_allowed_public_port(from, to) if {
	from <= 443
	to >= 443
}

_is_create_or_update(resource) if {
	resource.change.actions[_] in {"create", "update"}
}
