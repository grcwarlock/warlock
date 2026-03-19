package ucf.hrs.ucf_hrs_3

import rego.v1

# UCF-HRS-3: Security Awareness Training
# Validates training completion rates and phishing resilience

deny_low_completion contains msg if {
	input.normalized_data.training.completion_rate < 0.9
	msg := sprintf("UCF-HRS-3: Training completion rate is %.0f%% (require 90%%+)", [input.normalized_data.training.completion_rate * 100])
}

deny_high_phish_rate contains msg if {
	input.normalized_data.phishing.click_rate > 0.05
	msg := sprintf("UCF-HRS-3: Phishing click rate is %.1f%% (threshold 5%%)", [input.normalized_data.phishing.click_rate * 100])
}

default compliant := false

compliant if {
	count(deny_low_completion) == 0
	count(deny_high_phish_rate) == 0
}

findings := array.concat(
	[f | some f in deny_low_completion],
	[f | some f in deny_high_phish_rate],
)

result := {
	"control_id": "UCF-HRS-3",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
