package warlock.eu_ai_act.art52

import rego.v1

# Art. 52: Transparency Obligations for Certain AI Systems
# Applies to all risk levels — users must be informed they are interacting with AI

# 52.1: AI systems intended to interact with persons — must inform
deny_no_ai_disclosure contains msg if {
	some system in input.normalized_data.ai_systems
	system.interacts_with_humans
	not system.transparency_disclosure
	msg := sprintf("Art.52.1: AI system '%s' does not inform users of AI interaction", [system.name])
}

# 52.2: Emotion recognition or biometric categorization — must inform
deny_no_biometric_disclosure contains msg if {
	some system in input.normalized_data.ai_systems
	system.uses_biometric_data
	not system.biometric_disclosure
	msg := sprintf("Art.52.2: AI system '%s' uses biometric data without disclosure", [system.name])
}

# 52.3: Deep fakes — must label as artificially generated
deny_no_deepfake_label contains msg if {
	some system in input.normalized_data.ai_systems
	system.generates_synthetic_content
	not system.synthetic_content_labeled
	msg := sprintf("Art.52.3: AI system '%s' generates synthetic content without labeling", [system.name])
}

default compliant := false

compliant if {
	count(deny_no_ai_disclosure) == 0
	count(deny_no_biometric_disclosure) == 0
	count(deny_no_deepfake_label) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_ai_disclosure],
		[f | some f in deny_no_biometric_disclosure],
	),
	[f | some f in deny_no_deepfake_label],
)

result := {
	"control_id": "Art.52",
	"framework": "EU AI Act",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
