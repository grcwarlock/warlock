package nist.sa.sa_2

import rego.v1

# SA-2: Allocation of Resources

deny_no_resource_allocation contains msg if {
	not input.normalized_data.security_resource_allocation
	msg := "SA-2: No security and privacy resource allocation in mission and business process planning"
}

deny_no_budget_allocation contains msg if {
	alloc := input.normalized_data.security_resource_allocation
	not alloc.budget_allocated
	msg := "SA-2: Security and privacy budget not allocated in capital planning"
}

deny_no_staffing_allocation contains msg if {
	alloc := input.normalized_data.security_resource_allocation
	not alloc.staffing_allocated
	msg := "SA-2: Staffing resources not allocated for security and privacy"
}

deny_allocation_not_documented contains msg if {
	alloc := input.normalized_data.security_resource_allocation
	not alloc.documented_in_programming
	msg := "SA-2: Security resource allocation not documented in programming and budgeting documentation"
}

default compliant := false

compliant if {
	count(deny_no_resource_allocation) == 0
	count(deny_no_budget_allocation) == 0
	count(deny_no_staffing_allocation) == 0
	count(deny_allocation_not_documented) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_resource_allocation],
		[f | some f in deny_no_budget_allocation],
	),
	array.concat(
		[f | some f in deny_no_staffing_allocation],
		[f | some f in deny_allocation_not_documented],
	),
)

result := {
	"control_id": "SA-2",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
