# Assessment Engine

The assessment engine is Warlock's fourth pipeline stage. It takes mapped findings (a finding linked to a specific compliance control) and produces a determination: compliant, non-compliant, partial, or not assessed. The engine uses a four-tier evaluation model that prioritizes deterministic, auditable checks and falls back to progressively softer methods when hard evidence is unavailable.

This document covers the four assessment tiers, how assertions bind to controls, status values, the evidence chain, and configuration options.

## Four-Tier Assessment Model

Each finding-to-control mapping passes through the tiers in order. The engine stops at the first tier that produces a definitive result.

```
Tier 1: Deterministic Assertions     Fast, auditable, reproducible
         |
         | (not_assessed?)
         v
Tier 2: AI Reasoning                 LLM-powered, context-aware
         |
         | (not_assessed?)
         v
Tier 3: OPA Rego Policies            Policy-as-code evaluation
         |
         | (not_assessed?)
         v
Tier 4: Control Inheritance          Parent-to-child status propagation
```

### Tier 1: Deterministic Assertions

Deterministic assertions are Python functions that evaluate finding data against specific compliance conditions. They are the foundation of the assessment engine -- fast, auditable, and fully reproducible.

**How they work**: Each assertion takes two arguments -- the finding's detail dictionary and the raw event data -- and returns a tuple of `(passed: bool, reasons: list[str])`. If `passed` is `True`, the control is compliant. If `False`, the reasons list explains why.

**Current count**: 102 assertion functions across 14 control families.

**Key property**: Assertions are deterministic. Given the same input, they always produce the same output. No external calls, no randomness, no model inference. This makes them ideal for audit evidence -- an auditor can inspect the assertion code and verify the logic independently.

#### Assertion Families

The 102 assertions are organized into functional groups:

| Family | Assertions | Example Checks |
|---|---|---|
| Access Control | `mfa_enabled`, `no_root_access_keys`, `least_privilege_enforced`, `session_timeout_configured`, `account_provisioning_automated`, `inactive_accounts_disabled`, `separation_of_duties`, `remote_access_authorized`, `conditional_access_enforced`, `api_key_rotation` | MFA enrollment, root key absence, session timeouts, account lifecycle |
| Audit and Logging | `cloudtrail_enabled`, `audit_log_retention_compliant`, `audit_log_tamper_protection`, `centralized_logging_active`, `failed_login_monitoring`, `admin_action_logging`, `time_synchronization`, `logging_coverage_complete`, `database_audit_logging` | Multi-region logging, log retention, tamper protection, centralized aggregation |
| Threat Detection | `guardduty_enabled`, `securityhub_enabled`, `threat_detection_alerts_configured`, `malware_detection_active`, `antivirus_definitions_current`, `network_intrusion_detection` | GuardDuty/SCC activation, alert configuration, malware scanning |
| Network Security | `no_open_security_groups`, `tls_version_current`, `network_segmentation_enforced`, `waf_enabled`, `dns_security_enabled`, `vpn_tunnel_active`, `network_flow_logging`, `egress_filtering_active`, `wireless_security_compliant` | Open port detection, TLS version, WAF presence, network flow logging |
| Data Protection | `encryption_at_rest`, `encryption_in_transit`, `kms_key_rotation_enabled`, `secrets_management_enforced`, `no_public_storage`, `dlp_policies_active`, `backup_encryption_enabled`, `data_classification_applied`, `data_minimization_verified` | Encryption status, key rotation, public bucket detection, DLP policies |
| Endpoint Security | `endpoint_protection_active`, `device_compliant`, `file_integrity_monitoring`, `mobile_device_management` | EDR deployment, device compliance, FIM activation |
| Vulnerability Management | `vulnerability_scan_current`, `no_critical_code_vulns`, `patch_management_current`, `vulnerability_remediation_sla`, `container_image_signed` | Scan recency, critical vuln presence, patch status, SLA compliance |
| Identity and Authentication | `password_policy_compliant`, `strong_authentication_required`, `service_account_managed`, `certificate_validity`, `default_credentials_removed`, `identity_federation_configured`, `mfa_for_privileged_actions`, `account_lockout_configured` | Password policy strength, certificate expiry, default credential removal |
| Configuration Management | `config_recorder_enabled`, `baseline_configuration_documented`, `configuration_change_tracked`, `unauthorized_software_blocked`, `software_whitelist_enforced`, `infrastructure_as_code_validated` | AWS Config status, baseline documentation, IaC validation |
| Personnel Security | `background_check_completed`, `employment_agreement_signed`, `training_completion_rate`, `phishing_failure_rate`, `termination_access_revoked`, `role_change_access_reviewed`, `security_clearance_verified`, `security_awareness_program` | Background check status, training completion, termination access revocation |
| Incident Response | `incident_response_tested`, `security_incident_tracked`, `siem_monitoring_active` | IR plan testing, incident tracking, SIEM coverage |
| Business Continuity | `backup_job_successful`, `disaster_recovery_tested`, `backup_offsite_stored`, `recovery_time_achievable`, `multi_region_resilience` | Backup success, DR testing, offsite storage, RTO validation |
| Risk and Governance | `privileged_access_managed`, `access_reviews_current`, `risk_assessment_current`, `penetration_test_current`, `policy_reviewed_within_year`, `vendor_risk_assessed`, `third_party_sla_monitored`, `privileged_session_recorded`, `rbac_configured`, `asset_inventory_complete`, `secure_sdlc_implemented`, `spam_protection_active`, `input_validation_enforced` | Access reviews, pen test recency, vendor risk, SDLC maturity |
| Privacy and AI | `consent_mechanism_active`, `ai_model_inventory_current`, `shadow_ai_detected`, `physical_access_controlled`, `visitor_access_logged`, `change_request_approved` | Consent tracking, AI inventory, shadow AI detection, physical access |

#### Cross-Provider Assertion Design

Assertions are designed to work across multiple providers. For example, the `mfa_enabled` assertion handles:

- **AWS IAM**: Checks `mfa_active` and `password_enabled` fields from credential reports
- **Okta**: Checks `factors` or `enrolled_factors` arrays from user profiles
- **Entra ID**: Checks `authenticationMethods`, `strongAuthenticationDetail`, and conditional access `grantControls`
- **Generic**: Falls back to checking a `mfa_enabled` boolean field

This cross-provider design means one assertion covers the same security check regardless of which identity provider the organization uses.

#### Fail-Closed Behavior

When an assertion encounters insufficient data, it defaults to failing the control rather than passing it. The `mfa_enabled` assertion, for example, returns `False` with the reason "Insufficient data to determine MFA status" when it cannot find any recognizable MFA fields. This fail-closed design ensures that missing evidence never results in a false compliance determination.

### Tier 2: AI Reasoning

When no assertion is available for a control, or when Tier 1 produces a `not_assessed` result, Tier 2 uses a large language model to evaluate the finding against the control.

**Supported providers**: Anthropic (Claude), OpenAI (GPT), Google (Gemini), Ollama (local models). All calls go through `httpx` -- no vendor SDKs required.

**How it works**:

1. The AI reasoner constructs a prompt with the finding data, the control description, and broader compliance context (compensating controls, risk acceptances, posture trends, monitoring cadence, inheritance information)
2. The LLM responds with a JSON object containing status, narrative assessment, confidence score, and recommended action
3. The engine checks the confidence score against the configured floor

**Compliance context**: Unlike Tier 1 assertions that evaluate raw data in isolation, Tier 2 AI reasoning receives the full compliance context. An AI assessment considers:

- **Compensating controls**: If a compensating control exists, the AI may assess `partial` compliance even when the primary finding indicates non-compliance
- **Risk acceptances**: Active risk acceptances are noted but do not change the technical compliance assessment
- **Control inheritance**: Provider compliance status informs the assessment for inherited controls
- **Posture trends**: A recently compliant control that just drifted is assessed differently from one that has been non-compliant for months
- **Monitoring cadence**: Stale evidence reduces confidence

**Prompt sanitization**: All LLM prompts use `<evidence>` tags and control character stripping to prevent prompt injection from finding data. API keys are passed in headers (never in URL query parameters).

#### Confidence Floor

The AI confidence floor (default: 0.7) rejects assessments where the LLM reports low confidence. If the AI returns a confidence of 0.5, the result reverts to `not_assessed` and the assessor is tagged as `ai:low_confidence:{model}`.

This prevents unreliable AI assessments from marking controls as compliant when the model is uncertain. The floor is configurable via `WLK_AI_CONFIDENCE_FLOOR`.

#### AI Temperature

AI temperature is set to 0.0 by default (`WLK_AI_TEMPERATURE`), making compliance assessments deterministic. The same finding and control will produce the same assessment on repeated runs. Raising the temperature introduces non-determinism, which is inappropriate for compliance determinations.

#### Inline vs Batch Assessment

AI reasoning can run in two modes:

- **Inline** (default): AI evaluates each control during the pipeline run. Suitable for smaller deployments.
- **Batch**: AI is disabled during the pipeline run (`WLK_AI_INLINE_DISABLED=true`). Instead, batch assessment runs post-pipeline via `warlock lake assess` over the curated data lake zone. Suitable for large deployments where inline AI evaluation would slow the pipeline.

### Tier 3: OPA Rego Policies

670 OPA Rego policy files across 8 frameworks provide policy-as-code compliance evaluation. OPA policies evaluate structured input (normalized finding data) against declarative rules.

**Frameworks with OPA policies**:

| Framework | Policy Files |
|---|---|
| NIST 800-53 | 286 |
| ISO 27001 | 186 |
| CMMC Level 2 | 50 |
| HIPAA | 40 |
| SOC 2 | 26 |
| UCF | 24 |
| PCI DSS v4.0 | 24 |
| Total | 636 |

**How it works**: The OPA compliance evaluator sends finding data as structured input to the OPA engine, which evaluates it against the relevant policy for the control being assessed. The policy returns a compliance determination.

**Fail mode**: The OPA compliance evaluation fail mode is set to `open` by default (`WLK_OPA_COMPLIANCE_FAIL_MODE=open`). This means OPA compliance evaluation is optional -- if OPA is unreachable or no policy exists, the result passes through to Tier 4 rather than blocking. This is distinct from the OPA API enforcement gate, which defaults to `closed` (deny all if OPA is unreachable).

### Tier 4: Control Inheritance

The final tier handles parent-to-child control inheritance, following the FedRAMP Customer Responsibility Matrix (CRM) pattern.

**How it works**: NIST 800-53 controls have a parent/enhancement hierarchy. AC-2 is a base control; AC-2(1), AC-2(2), AC-2(3) are enhancements. When an enhancement control reaches Tier 4 without a determination, the engine checks if the parent control has been assessed:

- If the parent (AC-2) is `compliant`, the child (AC-2(3)) inherits `compliant` with confidence reduced by 0.1
- If the parent is `non_compliant`, the child inherits `non_compliant`
- If the parent is `not_assessed`, no inheritance occurs

The assessor field records the inheritance: `inherited:AC-2`.

**Cloud provider inheritance**: Warlock also tracks which controls are fully inherited from cloud providers. For example, all PE-* (Physical and Environmental Protection) controls are fully inherited from AWS, Azure, or GCP because the customer has no responsibility for the provider's data center physical security. These controls receive the status `inherited_compliant`.

Shared controls (e.g., AC-2 in AWS -- the provider manages the IAM service, but the customer manages user accounts) are assessed based on the customer's implementation of their portion.

## How Assertions Bind to Controls

Assertions are registered with the singleton `AssertionEngine` and then bound to specific framework controls. The binding is list-based: multiple assertions can be bound to the same control, and all must pass for the control to be marked compliant.

### Registration

Assertions are registered using the `@engine.assertion` decorator:

```python
@engine.assertion("mfa_enabled")
def mfa_enabled(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    # Check MFA status across providers
    ...
```

### Binding

Assertions are bound to controls via `engine.bind_control()`:

```python
engine.bind_control("nist_800_53", "AC-2", "mfa_enabled")
engine.bind_control("nist_800_53", "AC-2", "inactive_accounts_disabled")
engine.bind_control("soc2", "CC6.1", "mfa_enabled")
```

In this example, NIST AC-2 has two assertions: `mfa_enabled` and `inactive_accounts_disabled`. Both must pass for AC-2 to be compliant. SOC 2 CC6.1 has one assertion: `mfa_enabled`.

### Multiple Assertions Per Control

A control can have any number of assertions. When the assessor evaluates a control with multiple bindings:

1. All bound assertions run against the finding
2. If **all** assertions pass, the status is `compliant`
3. If **any** assertion fails, the status is `non_compliant`
4. The `assertion_name` field records all assertions that ran (comma-separated)
5. Remediation information comes from the first failed assertion

This list-based design prevents a common GRC platform bug where later assertion bindings silently overwrite earlier ones. Appending instead of overwriting ensures that a control like AC-2 keeps both its MFA check and its inactive account check.

### Remediation Attached to Assertions

Each assertion can have remediation information registered:

```python
engine.set_remediation("mfa_enabled", {
    "summary": "Enable MFA for all users with console access",
    "steps": [
        "Navigate to the IAM console",
        "Select the user without MFA",
        "Click 'Security credentials' tab",
        "Enable MFA device"
    ],
    "console_path": "https://console.aws.amazon.com/iam/home#/users"
})
```

When a control fails, the result includes the remediation summary, step-by-step instructions, and a direct link to the relevant console page.

## Status Values

Every control result carries one of seven status values:

| Status | Assigned By | Meaning |
|---|---|---|
| `compliant` | Tier 1, 2, 3, or 4 | Evidence confirms the control is implemented and effective |
| `non_compliant` | Tier 1, 2, or 3 | Evidence indicates the control is not implemented or has material gaps |
| `partial` | Tier 2 or 3 | Some aspects of the control are implemented but significant gaps remain |
| `not_assessed` | Default | No tier could produce a determination; evidence may be insufficient |
| `not_applicable` | Manual or workflow | The control does not apply to this system or context |
| `risk_accepted` | Risk acceptance workflow | The control gap is formally accepted with AO approval and expiration |
| `inherited_compliant` | Tier 4 or inheritance workflow | The control is satisfied by an underlying provider's authorization |

### Status Precedence

When multiple findings map to the same control (common when a control has checks across multiple event types), the most conservative status wins:

- `non_compliant` takes precedence over `partial`
- `partial` takes precedence over `compliant`
- `not_assessed` does not override any assessed status
- `risk_accepted` and `inherited_compliant` are set by workflows, not the assessment engine

## The Evidence Chain

Every control result maintains full traceability back to the raw API response that generated it. The chain has four links:

```
RawEventData        (verbatim API response, SHA-256 hashed)
     |
     v
FindingData         (normalized, provider-independent)
     |
     v
ControlMappingData  (finding linked to a specific control)
     |
     v
ControlResultData   (compliance determination with full lineage)
```

### ControlResultData Fields

| Field | Purpose |
|---|---|
| `finding_id` | Links to the FindingData that was assessed |
| `control_mapping_id` | Links to the ControlMappingData that triggered this assessment |
| `framework` | Which framework this control belongs to |
| `control_id` | The specific control identifier (e.g., "AC-2", "CC6.1") |
| `status` | The compliance determination |
| `severity` | Severity from the underlying finding |
| `assertion_name` | Which assertions ran (comma-separated if multiple) |
| `assertion_passed` | Boolean result of Tier 1 evaluation |
| `assertion_findings` | List of reasons from assertion evaluation |
| `ai_assessment` | Narrative explanation from Tier 2 AI reasoning |
| `ai_confidence` | Confidence score from AI (0.0 to 1.0) |
| `ai_model` | Which AI model produced the assessment |
| `remediation_summary` | Short description of the remediation action |
| `remediation_steps` | Step-by-step remediation instructions |
| `console_path` | Direct URL to the relevant management console |
| `evidence_ids` | List of raw event IDs that constitute evidence |
| `assessed_at` | UTC timestamp of assessment |
| `assessor` | Which tier produced the result (e.g., `assertion:mfa_enabled`, `ai:claude-sonnet-4-20250514`, `inherited:AC-2`) |
| `id` | UUID of this result |

The `assessor` field is particularly important for audit purposes. It tells you exactly how the compliance determination was made:

- `assertion:mfa_enabled` -- Tier 1 deterministic check
- `assertion:mfa_enabled,inactive_accounts_disabled` -- Tier 1 with multiple assertions
- `ai:gpt-4o` -- Tier 2 AI reasoning with GPT-4o
- `ai:low_confidence:claude-sonnet-4-20250514` -- Tier 2 AI rejected due to low confidence
- `inherited:AC-2` -- Tier 4 inherited from parent control
- `none` -- No tier could assess; status is `not_assessed`

## Configuration Reference

| Setting | Environment Variable | Default | Purpose |
|---|---|---|---|
| AI provider | `WLK_AI_PROVIDER` | (none) | Which LLM provider: `anthropic`, `openai`, `gemini`, `ollama` |
| AI API key | `WLK_AI_API_KEY` | (none) | API key for the configured provider |
| AI model | `WLK_AI_MODEL` | (varies) | Model identifier (e.g., `claude-sonnet-4-20250514`, `gpt-4o`) |
| AI base URL | `WLK_AI_BASE_URL` | (varies) | API endpoint URL |
| Confidence floor | `WLK_AI_CONFIDENCE_FLOOR` | `0.7` | Minimum AI confidence to accept an assessment |
| Temperature | `WLK_AI_TEMPERATURE` | `0.0` | LLM temperature (0.0 = deterministic) |
| Inline AI disabled | `WLK_AI_INLINE_DISABLED` | `false` | Skip AI during pipeline; use batch mode instead |
| OPA compliance fail mode | `WLK_OPA_COMPLIANCE_FAIL_MODE` | `open` | Behavior when OPA is unreachable: `open` (pass through) or `closed` (fail) |

### Security-Critical Defaults

These defaults exist for security reasons. Changing them has compliance implications:

- **`ai_confidence_floor = 0.7`**: Lowering this accepts AI assessments the model itself is uncertain about. An AI assessment with 0.4 confidence is unreliable -- do not mark controls compliant based on it.

- **`ai_temperature = 0.0`**: Raising this makes compliance assessments non-deterministic. The same finding evaluated twice may produce different results, which undermines auditability.

- **`opa_compliance_fail_mode = open`**: This is intentionally open because OPA compliance evaluation is optional. The API enforcement OPA gate (`WLK_OPA_FAIL_MODE`) is separate and defaults to `closed` (deny all if OPA is unreachable).

## Pipeline Integration

The assessment engine is the final stage of the four-stage pipeline:

1. **Connectors** collect raw events and publish `raw_event_collected` events
2. **Normalizers** transform raw events into findings and publish `finding_normalized` events
3. **Control mapper** links findings to framework controls and publishes `control_mapped` events
4. **Assessor** evaluates each mapping and publishes `control_assessed` events

The pipeline orchestrator passes each mapped finding to the `Assessor.assess()` or `Assessor.assess_with_inheritance()` method, which returns a list of `ControlResultData` -- one per control mapping. Results are persisted to the database and published to the event bus for downstream consumers (alerting, data lake, posture tracking).

### Inheritance-Aware Assessment

The `assess_with_inheritance()` method accepts a dictionary of pre-computed parent results. During a pipeline run, the orchestrator first assesses all base controls (e.g., AC-2, SC-7), collects their results, and then passes them as parent results when assessing enhancement controls (e.g., AC-2(3), SC-7(5)). This two-pass approach ensures parent results are available for Tier 4 inheritance.

### Event Bus Integration

After assessment, results are published to the event bus as `PipelineEvent` objects. Subscribers can react to compliance changes:

- **Alerting**: Send notifications when controls transition from compliant to non-compliant
- **Data lake**: Write results to the analytical layer for trend analysis
- **Posture tracking**: Update posture scores and detect compliance drift
- **POA&M creation**: Automatically create remediation plans for non-compliant controls
