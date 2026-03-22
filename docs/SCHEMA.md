# Warlock Database Schema

**36 tables, 488 columns** across 11 Alembic migrations.
SQLite (dev), PostgreSQL (prod). JSON columns map to JSONB on Postgres.

---

## Pipeline (5 tables)

### connector_runs

| Column | Type | Constraints |
|--------|------|-------------|
| id | VARCHAR(36) | PK |
| connector_name | VARCHAR(100) | NOT NULL |
| source | VARCHAR(50) | NOT NULL |
| source_type | VARCHAR(20) | NOT NULL |
| provider | VARCHAR(50) | NOT NULL |
| status | VARCHAR(20) | NOT NULL |
| event_count | INTEGER |  |
| error_count | INTEGER |  |
| errors | JSON |  |
| started_at | DATETIME | NOT NULL |
| completed_at | DATETIME |  |
| duration_seconds | FLOAT |  |

### raw_events

| Column | Type | Constraints |
|--------|------|-------------|
| id | VARCHAR(36) | PK |
| connector_run_id | VARCHAR(36) | FK -> connector_runs.id, NOT NULL |
| source | VARCHAR(50) | NOT NULL |
| source_type | VARCHAR(20) | NOT NULL |
| provider | VARCHAR(50) | NOT NULL |
| event_type | VARCHAR(100) | NOT NULL |
| raw_data | JSON | NOT NULL |
| sha256 | VARCHAR(64) | NOT NULL |
| ingested_at | DATETIME | NOT NULL |

### findings

| Column | Type | Constraints |
|--------|------|-------------|
| id | VARCHAR(36) | PK |
| raw_event_id | VARCHAR(36) | FK -> raw_events.id, NOT NULL |
| observation_type | VARCHAR(50) | NOT NULL |
| title | TEXT | NOT NULL |
| detail | JSON | NOT NULL |
| resource_id | TEXT |  |
| resource_type | VARCHAR(100) |  |
| resource_name | TEXT |  |
| account_id | VARCHAR(100) |  |
| region | VARCHAR(50) |  |
| system_profile_id | VARCHAR(36) | FK -> system_profiles.id |
| source | VARCHAR(50) | NOT NULL |
| source_type | VARCHAR(20) | NOT NULL |
| provider | VARCHAR(50) | NOT NULL |
| severity | VARCHAR(20) | NOT NULL |
| confidence | FLOAT |  |
| observed_at | DATETIME | NOT NULL |
| ingested_at | DATETIME | NOT NULL |
| sha256 | VARCHAR(64) | NOT NULL |

### control_mappings

| Column | Type | Constraints |
|--------|------|-------------|
| id | VARCHAR(36) | PK |
| finding_id | VARCHAR(36) | FK -> findings.id, NOT NULL |
| framework | VARCHAR(50) | NOT NULL |
| control_id | VARCHAR(50) | NOT NULL |
| control_family | VARCHAR(50) |  |
| mapping_method | VARCHAR(30) | NOT NULL |
| confidence | FLOAT | NOT NULL |
| crosswalk_path | JSON |  |
| monitoring_frequency | VARCHAR(20) |  |
| created_at | DATETIME | NOT NULL |

### control_results

| Column | Type | Constraints |
|--------|------|-------------|
| id | VARCHAR(36) | PK |
| finding_id | VARCHAR(36) | FK -> findings.id, NOT NULL |
| control_mapping_id | VARCHAR(36) | FK -> control_mappings.id, NOT NULL |
| framework | VARCHAR(50) | NOT NULL |
| control_id | VARCHAR(50) | NOT NULL |
| system_profile_id | VARCHAR(36) | FK -> system_profiles.id |
| status | VARCHAR(20) | NOT NULL |
| severity | VARCHAR(20) | NOT NULL |
| assertion_name | VARCHAR(255) |  |
| assertion_passed | BOOLEAN |  |
| assertion_findings | JSON |  |
| ai_assessment | TEXT |  |
| ai_confidence | FLOAT |  |
| ai_model | VARCHAR(50) |  |
| remediation_summary | TEXT |  |
| remediation_steps | JSON |  |
| console_path | TEXT |  |
| evidence_ids | JSON |  |
| assessed_at | DATETIME | NOT NULL |
| assessor | VARCHAR(255) | NOT NULL |
| examined_at | DATETIME |  |
| examined_by | VARCHAR(255) |  |

## Governance (8 tables)

### poams

| Column | Type | Constraints |
|--------|------|-------------|
| id | VARCHAR(36) | PK |
| finding_id | VARCHAR(36) | FK -> findings.id |
| control_result_id | VARCHAR(36) | FK -> control_results.id |
| framework | VARCHAR(50) | NOT NULL |
| control_id | VARCHAR(50) | NOT NULL |
| system_profile_id | VARCHAR(36) | FK -> system_profiles.id |
| weakness_description | TEXT | NOT NULL |
| severity | VARCHAR(20) | NOT NULL |
| risk_level | VARCHAR(20) |  |
| status | VARCHAR(20) | NOT NULL |
| milestones | JSON |  |
| scheduled_completion | DATETIME |  |
| actual_completion | DATETIME |  |
| delay_count | INTEGER |  |
| delay_justifications | JSON |  |
| resources_required | TEXT |  |
| created_by | VARCHAR(255) |  |
| updated_by | VARCHAR(255) |  |
| approved_by | VARCHAR(255) |  |
| approved_at | DATETIME |  |
| vendor_dependency | VARCHAR(255) |  |
| created_at | DATETIME | NOT NULL |
| updated_at | DATETIME |  |

### compensating_controls

| Column | Type | Constraints |
|--------|------|-------------|
| id | VARCHAR(36) | PK |
| original_framework | VARCHAR(50) | NOT NULL |
| original_control_id | VARCHAR(50) | NOT NULL |
| poam_id | VARCHAR(36) | FK -> poams.id |
| system_profile_id | VARCHAR(36) | FK -> system_profiles.id |
| title | VARCHAR(255) | NOT NULL |
| description | TEXT | NOT NULL |
| implementation_details | TEXT |  |
| evidence_references | JSON |  |
| status | VARCHAR(20) | NOT NULL |
| approved_by | VARCHAR(255) |  |
| approved_at | DATETIME |  |
| expiry_date | DATETIME |  |
| review_frequency | VARCHAR(20) |  |
| last_reviewed | DATETIME |  |
| effectiveness_score | FLOAT |  |
| created_by | VARCHAR(255) |  |
| created_at | DATETIME | NOT NULL |
| updated_at | DATETIME |  |

### risk_acceptances

| Column | Type | Constraints |
|--------|------|-------------|
| id | VARCHAR(36) | PK |
| framework | VARCHAR(50) | NOT NULL |
| control_id | VARCHAR(50) | NOT NULL |
| poam_id | VARCHAR(36) | FK -> poams.id |
| system_profile_id | VARCHAR(36) | FK -> system_profiles.id |
| risk_description | TEXT | NOT NULL |
| risk_level | VARCHAR(20) | NOT NULL |
| residual_risk_level | VARCHAR(20) |  |
| conditions | JSON |  |
| status | VARCHAR(20) | NOT NULL |
| requested_by | VARCHAR(255) | NOT NULL |
| reviewed_by | VARCHAR(255) |  |
| reviewed_at | DATETIME |  |
| approved_by | VARCHAR(255) |  |
| approved_at | DATETIME |  |
| expiry_date | DATETIME | NOT NULL |
| auto_reeval_triggers | JSON |  |
| created_at | DATETIME | NOT NULL |
| updated_at | DATETIME |  |

### control_inheritances

| Column | Type | Constraints |
|--------|------|-------------|
| id | VARCHAR(36) | PK |
| system_profile_id | VARCHAR(36) | FK -> system_profiles.id, NOT NULL |
| framework | VARCHAR(50) | NOT NULL |
| control_id | VARCHAR(50) | NOT NULL |
| inheritance_type | VARCHAR(20) | NOT NULL |
| provider_system_id | VARCHAR(36) | FK -> system_profiles.id |
| provider_description | TEXT |  |
| responsibility_description | TEXT |  |
| evidence_requirement | VARCHAR(20) |  |
| status | VARCHAR(20) |  |
| created_at | DATETIME | NOT NULL |
| updated_at | DATETIME |  |

### system_dependencies

| Column | Type | Constraints |
|--------|------|-------------|
| id | VARCHAR(36) | PK |
| consumer_system_id | VARCHAR(36) | FK -> system_profiles.id, NOT NULL |
| provider_system_id | VARCHAR(36) | FK -> system_profiles.id, NOT NULL |
| shared_controls | JSON |  |
| dependency_type | VARCHAR(30) | NOT NULL |
| description | TEXT |  |
| created_at | DATETIME | NOT NULL |

### issues

| Column | Type | Constraints |
|--------|------|-------------|
| id | VARCHAR(36) | PK |
| title | TEXT | NOT NULL |
| description | TEXT |  |
| finding_id | VARCHAR(36) | FK -> findings.id |
| control_result_id | VARCHAR(36) | FK -> control_results.id |
| poam_id | VARCHAR(36) | FK -> poams.id |
| framework | VARCHAR(50) |  |
| control_id | VARCHAR(50) |  |
| status | VARCHAR(20) | NOT NULL |
| priority | VARCHAR(20) | NOT NULL |
| assigned_to | VARCHAR(255) |  |
| assigned_by | VARCHAR(255) |  |
| assigned_at | DATETIME |  |
| due_date | DATETIME |  |
| remediated_at | DATETIME |  |
| verified_at | DATETIME |  |
| closed_at | DATETIME |  |
| risk_accepted | BOOLEAN |  |
| risk_acceptance_owner | VARCHAR(255) |  |
| risk_acceptance_expiry | DATETIME |  |
| risk_acceptance_justification | TEXT |  |
| remediation_plan | TEXT |  |
| remediation_evidence | JSON |  |
| verification_notes | TEXT |  |
| source | VARCHAR(50) |  |
| tags | JSON |  |
| created_at | DATETIME | NOT NULL |
| updated_at | DATETIME |  |
| created_by | VARCHAR(255) |  |

### issue_comments

| Column | Type | Constraints |
|--------|------|-------------|
| id | VARCHAR(36) | PK |
| issue_id | VARCHAR(36) | FK -> issues.id, NOT NULL |
| author | VARCHAR(255) | NOT NULL |
| content | TEXT | NOT NULL |
| comment_type | VARCHAR(20) |  |
| created_at | DATETIME | NOT NULL |

### policy_overrides

| Column | Type | Constraints |
|--------|------|-------------|
| id | VARCHAR(36) | PK |
| name | VARCHAR(255) | NOT NULL |
| description | TEXT |  |
| policy_rego | TEXT | NOT NULL |
| is_active | BOOLEAN |  |
| created_by | VARCHAR(255) |  |
| created_at | DATETIME | NOT NULL |

## Audit & Attestation (6 tables)

### audit_entries

| Column | Type | Constraints |
|--------|------|-------------|
| id | VARCHAR(36) | PK |
| sequence | BIGINT | NOT NULL |
| previous_hash | VARCHAR(64) | NOT NULL |
| entry_hash | VARCHAR(64) | NOT NULL |
| action | VARCHAR(50) | NOT NULL |
| entity_type | VARCHAR(50) | NOT NULL |
| entity_id | VARCHAR(36) | NOT NULL |
| actor | VARCHAR(100) | NOT NULL |
| evidence_sha256 | VARCHAR(64) |  |
| extra | JSON |  |
| created_at | DATETIME | NOT NULL |

### audit_engagements

| Column | Type | Constraints |
|--------|------|-------------|
| id | VARCHAR(36) | PK |
| name | VARCHAR(255) | NOT NULL |
| framework | VARCHAR(50) | NOT NULL |
| period_start | DATETIME | NOT NULL |
| period_end | DATETIME | NOT NULL |
| status | VARCHAR(20) | NOT NULL |
| in_scope_controls | JSON |  |
| excluded_controls | JSON |  |
| auditor_name | VARCHAR(255) |  |
| auditor_firm | VARCHAR(255) |  |
| created_at | DATETIME | NOT NULL |
| completed_at | DATETIME |  |

### attestations

| Column | Type | Constraints |
|--------|------|-------------|
| id | VARCHAR(36) | PK |
| engagement_id | VARCHAR(36) | FK -> audit_engagements.id |
| framework | VARCHAR(50) | NOT NULL |
| control_id | VARCHAR(50) |  |
| status | VARCHAR(20) | NOT NULL |
| statement | TEXT | NOT NULL |
| evidence_references | JSON |  |
| prepared_by | VARCHAR(255) |  |
| prepared_at | DATETIME |  |
| submitted_by | VARCHAR(255) |  |
| submitted_at | DATETIME |  |
| reviewed_by | VARCHAR(255) |  |
| reviewed_at | DATETIME |  |
| review_notes | TEXT |  |
| approved_by | VARCHAR(255) |  |
| approved_at | DATETIME |  |
| rejected_by | VARCHAR(255) |  |
| rejected_at | DATETIME |  |
| rejection_reason | TEXT |  |
| created_at | DATETIME | NOT NULL |
| updated_at | DATETIME |  |

### audit_comments

| Column | Type | Constraints |
|--------|------|-------------|
| id | VARCHAR(36) | PK |
| engagement_id | VARCHAR(36) | FK -> audit_engagements.id, NOT NULL |
| target_type | VARCHAR(30) | NOT NULL |
| target_id | VARCHAR(50) | NOT NULL |
| author | VARCHAR(255) | NOT NULL |
| author_role | VARCHAR(20) |  |
| external_auditor_id | VARCHAR(36) | FK -> external_auditors.id |
| content | TEXT | NOT NULL |
| parent_id | VARCHAR(36) |  |
| resolved | BOOLEAN |  |
| resolved_by | VARCHAR(255) |  |
| resolved_at | DATETIME |  |
| created_at | DATETIME | NOT NULL |

### external_auditors

| Column | Type | Constraints |
|--------|------|-------------|
| id | VARCHAR(36) | PK |
| email | VARCHAR(255) | NOT NULL |
| name | VARCHAR(255) | NOT NULL |
| firm | VARCHAR(255) |  |
| magic_link_hash | VARCHAR(64) |  |
| token_expires_at | DATETIME |  |
| last_accessed | DATETIME |  |
| is_active | BOOLEAN |  |
| created_at | DATETIME | NOT NULL |

### auditor_engagement_assignments

| Column | Type | Constraints |
|--------|------|-------------|
| auditor_id | VARCHAR(36) | PK, FK -> external_auditors.id |
| engagement_id | VARCHAR(36) | PK, FK -> audit_engagements.id |
| assigned_at | DATETIME | NOT NULL |

## Intelligence (3 tables)

### posture_snapshots

| Column | Type | Constraints |
|--------|------|-------------|
| id | VARCHAR(36) | PK |
| snapshot_date | DATETIME | NOT NULL |
| framework | VARCHAR(50) | NOT NULL |
| control_id | VARCHAR(50) | NOT NULL |
| status | VARCHAR(20) | NOT NULL |
| posture_score | FLOAT | NOT NULL |
| total_findings | INTEGER |  |
| compliant_findings | INTEGER |  |
| non_compliant_findings | INTEGER |  |
| partial_findings | INTEGER |  |
| not_assessed_findings | INTEGER |  |
| evidence_sources | JSON |  |
| evidence_freshness_hours | FLOAT |  |
| sufficiency_score | FLOAT |  |
| sufficiency_details | JSON |  |
| system_profile_id | VARCHAR(36) | FK -> system_profiles.id |
| uptime_pct | FLOAT |  |
| mttr_hours | FLOAT |  |
| drift_count | INTEGER |  |
| created_at | DATETIME | NOT NULL |

### compliance_drifts

| Column | Type | Constraints |
|--------|------|-------------|
| id | VARCHAR(36) | PK |
| framework | VARCHAR(50) | NOT NULL |
| control_id | VARCHAR(50) | NOT NULL |
| system_profile_id | VARCHAR(36) | FK -> system_profiles.id |
| previous_status | VARCHAR(20) | NOT NULL |
| new_status | VARCHAR(20) | NOT NULL |
| drift_direction | VARCHAR(20) | NOT NULL |
| previous_posture_score | FLOAT |  |
| new_posture_score | FLOAT |  |
| correlated_change_event_ids | JSON |  |
| root_cause_summary | TEXT |  |
| correlation_confidence | FLOAT |  |
| detected_at | DATETIME | NOT NULL |
| snapshot_id | VARCHAR(36) |  |

### change_events

| Column | Type | Constraints |
|--------|------|-------------|
| id | VARCHAR(36) | PK |
| source | VARCHAR(50) | NOT NULL |
| source_type | VARCHAR(30) | NOT NULL |
| event_type | VARCHAR(100) | NOT NULL |
| actor | VARCHAR(255) |  |
| action | VARCHAR(255) | NOT NULL |
| resource_id | TEXT |  |
| resource_type | VARCHAR(100) |  |
| detail | JSON |  |
| occurred_at | DATETIME | NOT NULL |
| ingested_at | DATETIME | NOT NULL |
| sha256 | VARCHAR(64) | NOT NULL |

## Identity & Access (3 tables)

### users

| Column | Type | Constraints |
|--------|------|-------------|
| id | VARCHAR(36) | PK |
| email | VARCHAR(255) | NOT NULL |
| name | VARCHAR(255) | NOT NULL |
| hashed_password | VARCHAR(255) | NOT NULL |
| role | VARCHAR(20) | NOT NULL |
| is_active | BOOLEAN |  |
| allowed_frameworks | JSON |  |
| allowed_sources | JSON |  |
| allowed_control_families | JSON |  |
| allowed_actions | JSON |  |
| created_at | DATETIME | NOT NULL |
| last_login | DATETIME |  |
| failed_login_count | INTEGER |  |
| locked_until | DATETIME |  |
| token_valid_after | DATETIME |  |
| mfa_enabled | BOOLEAN |  |
| mfa_secret | VARCHAR(64) |  |
| mfa_backup_codes | JSON |  |
| mfa_verified_at | DATETIME |  |
| refresh_token_hash | VARCHAR(64) |  |

### api_keys

| Column | Type | Constraints |
|--------|------|-------------|
| id | VARCHAR(36) | PK |
| user_id | VARCHAR(36) | FK -> users.id, NOT NULL |
| key_hash | VARCHAR(64) | NOT NULL |
| name | VARCHAR(100) | NOT NULL |
| scopes | JSON |  |
| is_active | BOOLEAN |  |
| expires_at | DATETIME |  |
| created_at | DATETIME | NOT NULL |
| last_used | DATETIME |  |

### evidence_requests

| Column | Type | Constraints |
|--------|------|-------------|
| id | VARCHAR(36) | PK |
| engagement_id | VARCHAR(36) | FK -> audit_engagements.id, NOT NULL |
| auditor_id | VARCHAR(36) | FK -> external_auditors.id, NOT NULL |
| framework | VARCHAR(50) |  |
| control_id | VARCHAR(50) |  |
| description | TEXT | NOT NULL |
| status | VARCHAR(20) |  |
| fulfilled_by | VARCHAR(255) |  |
| fulfilled_at | DATETIME |  |
| fulfillment_notes | TEXT |  |
| evidence_ids | JSON |  |
| created_at | DATETIME | NOT NULL |
| updated_at | DATETIME |  |

## Assets & People (5 tables)

### system_profiles

| Column | Type | Constraints |
|--------|------|-------------|
| id | VARCHAR(36) | PK |
| name | VARCHAR(255) | NOT NULL |
| acronym | VARCHAR(50) |  |
| description | TEXT |  |
| confidentiality_impact | VARCHAR(10) |  |
| integrity_impact | VARCHAR(10) |  |
| availability_impact | VARCHAR(10) |  |
| overall_impact | VARCHAR(10) |  |
| cloud_accounts | JSON |  |
| network_boundaries | JSON |  |
| interconnections | JSON |  |
| connector_scope | JSON |  |
| frameworks | JSON |  |
| system_owner | VARCHAR(255) |  |
| system_owner_email | VARCHAR(255) |  |
| isso | VARCHAR(255) |  |
| isso_email | VARCHAR(255) |  |
| issm | VARCHAR(255) |  |
| issm_email | VARCHAR(255) |  |
| authorizing_official | VARCHAR(255) |  |
| ao_email | VARCHAR(255) |  |
| authorization_status | VARCHAR(30) |  |
| authorization_date | DATETIME |  |
| authorization_expiry | DATETIME |  |
| continuous_monitoring_plan | TEXT |  |
| deployment_model | VARCHAR(30) |  |
| service_model | VARCHAR(20) |  |
| retention_policy_days | INTEGER |  |
| is_active | BOOLEAN |  |
| created_at | DATETIME | NOT NULL |
| updated_at | DATETIME |  |

### personnel

| Column | Type | Constraints |
|--------|------|-------------|
| id | VARCHAR(36) | PK |
| email | VARCHAR(255) | NOT NULL |
| full_name | VARCHAR(255) | NOT NULL |
| department | VARCHAR(100) |  |
| title | VARCHAR(255) |  |
| manager_email | VARCHAR(255) |  |
| employee_type | VARCHAR(30) |  |
| hr_employee_id | VARCHAR(100) |  |
| hire_date | DATETIME |  |
| termination_date | DATETIME |  |
| hr_status | VARCHAR(30) |  |
| background_check_status | VARCHAR(30) |  |
| background_check_date | DATETIME |  |
| agreements_signed | JSON |  |
| idp_user_id | VARCHAR(255) |  |
| idp_provider | VARCHAR(30) |  |
| idp_status | VARCHAR(30) |  |
| idp_last_login | DATETIME |  |
| mfa_enabled | BOOLEAN |  |
| idp_groups | JSON |  |
| training_status | VARCHAR(30) |  |
| last_training_date | DATETIME |  |
| phishing_score | FLOAT |  |
| training_completions | JSON |  |
| last_access_review | DATETIME |  |
| access_review_status | VARCHAR(30) |  |
| flags | JSON |  |
| risk_score | FLOAT |  |
| is_active | BOOLEAN |  |
| last_synced | DATETIME |  |
| created_at | DATETIME | NOT NULL |
| updated_at | DATETIME |  |

### data_silos

| Column | Type | Constraints |
|--------|------|-------------|
| id | VARCHAR(36) | PK |
| name | VARCHAR(255) | NOT NULL |
| silo_type | VARCHAR(30) | NOT NULL |
| provider | VARCHAR(30) |  |
| location | VARCHAR(500) |  |
| data_classification | VARCHAR(20) |  |
| contains_pii | BOOLEAN |  |
| contains_phi | BOOLEAN |  |
| contains_pci | BOOLEAN |  |
| contains_credentials | BOOLEAN |  |
| last_scan_date | DATETIME |  |
| scan_status | VARCHAR(20) |  |
| sensitive_field_count | INTEGER |  |
| total_records | INTEGER |  |
| scan_findings | JSON |  |
| encrypted_at_rest | BOOLEAN |  |
| encrypted_in_transit | BOOLEAN |  |
| access_logging_enabled | BOOLEAN |  |
| backup_enabled | BOOLEAN |  |
| retention_days | INTEGER |  |
| owner | VARCHAR(255) |  |
| team | VARCHAR(100) |  |
| applicable_frameworks | JSON |  |
| remediation_status | VARCHAR(20) |  |
| remediation_notes | TEXT |  |
| is_active | BOOLEAN |  |
| created_at | DATETIME | NOT NULL |
| updated_at | DATETIME |  |

### legal_holds

| Column | Type | Constraints |
|--------|------|-------------|
| id | VARCHAR(36) | PK |
| reason | TEXT | NOT NULL |
| start_date | DATETIME | NOT NULL |
| end_date | DATETIME |  |
| created_by | VARCHAR(255) |  |
| is_active | BOOLEAN |  |
| created_at | DATETIME | NOT NULL |
| framework | VARCHAR(50) |  |
| system_profile_id | VARCHAR(36) | FK -> system_profiles.id |
| date_range_start | DATETIME |  |
| date_range_end | DATETIME |  |

### embeddings

| Column | Type | Constraints |
|--------|------|-------------|
| id | VARCHAR(36) | PK |
| entity_type | VARCHAR(50) | NOT NULL |
| entity_id | VARCHAR(100) | NOT NULL |
| entity_text | TEXT | NOT NULL |
| vector | JSON | NOT NULL |
| model_name | VARCHAR(100) | NOT NULL |
| dimensions | INTEGER | NOT NULL |
| created_at | DATETIME |  |

## Risk & Analytics (2 tables)

### risk_analyses

| Column | Type | Constraints |
|--------|------|-------------|
| id | VARCHAR(36) | PK |
| framework | VARCHAR(50) | NOT NULL |
| scenario_name | VARCHAR(255) | NOT NULL |
| mean_ale | FLOAT | NOT NULL |
| var_95 | FLOAT | NOT NULL |
| var_99 | FLOAT | NOT NULL |
| control_effectiveness | FLOAT |  |
| iterations | INTEGER |  |
| details | JSON |  |
| created_at | DATETIME | NOT NULL |

### questionnaire_templates

| Column | Type | Constraints |
|--------|------|-------------|
| id | VARCHAR(36) | PK |
| name | VARCHAR(255) | NOT NULL |
| template_type | VARCHAR(30) | NOT NULL |
| version | VARCHAR(20) |  |
| description | TEXT |  |
| questions | JSON | NOT NULL |
| total_questions | INTEGER |  |
| is_active | BOOLEAN |  |
| created_at | DATETIME | NOT NULL |

## Trust Portal (3 tables)

### trust_access_requests

| Column | Type | Constraints |
|--------|------|-------------|
| id | VARCHAR(36) | PK |
| company_name | VARCHAR(255) | NOT NULL |
| contact_name | VARCHAR(255) | NOT NULL |
| contact_email | VARCHAR(255) | NOT NULL |
| document_types | JSON |  |
| reason | TEXT |  |
| nda_accepted | BOOLEAN |  |
| status | VARCHAR(20) | NOT NULL |
| reviewed_by | VARCHAR(255) |  |
| reviewed_at | DATETIME |  |
| created_at | DATETIME | NOT NULL |

### trust_documents

| Column | Type | Constraints |
|--------|------|-------------|
| id | VARCHAR(36) | PK |
| title | VARCHAR(255) | NOT NULL |
| description | TEXT |  |
| classification_tier | VARCHAR(20) | NOT NULL |
| file_path | TEXT | NOT NULL |
| content_type | VARCHAR(100) |  |
| file_size_bytes | INTEGER |  |
| uploaded_by | VARCHAR(255) | NOT NULL |
| uploaded_at | DATETIME | NOT NULL |
| is_active | BOOLEAN |  |

### questionnaires

| Column | Type | Constraints |
|--------|------|-------------|
| id | VARCHAR(36) | PK |
| template_id | VARCHAR(36) | FK -> questionnaire_templates.id, NOT NULL |
| vendor_name | VARCHAR(255) | NOT NULL |
| vendor_contact_email | VARCHAR(255) |  |
| status | VARCHAR(20) | NOT NULL |
| responses | JSON |  |
| completion_pct | FLOAT |  |
| ai_suggested_answers | JSON |  |
| risk_score | FLOAT |  |
| risk_findings | JSON |  |
| sent_at | DATETIME |  |
| due_date | DATETIME |  |
| completed_at | DATETIME |  |
| reviewed_by | VARCHAR(255) |  |
| reviewed_at | DATETIME |  |
| created_at | DATETIME | NOT NULL |
| updated_at | DATETIME |  |
| created_by | VARCHAR(255) |  |

---

## Key Relationships

```
ConnectorRun 1--* RawEvent 1--* Finding 1--* ControlMapping 1--* ControlResult
                                   |
                                   +--* Issue --* IssueComment
                                   +--* POAM --* CompensatingControl
                                              +--* RiskAcceptance

SystemProfile 1--* ControlResult
              1--* ControlInheritance
              1--* PostureSnapshot
              1--* ComplianceDrift
              1--* POAM

AuditEngagement 1--* Attestation
                1--* AuditComment
                1--* EvidenceRequest
                *--* ExternalAuditor (via AuditorEngagementAssignment)

User 1--* APIKey
```

## JSON Columns (schemaless)

These columns accept arbitrary structures. Vendor-specific data lives here.

- api_keys.scopes
- attestations.evidence_references
- audit_engagements.in_scope_controls
- audit_engagements.excluded_controls
- audit_entries.extra
- change_events.detail
- compensating_controls.evidence_references
- compliance_drifts.correlated_change_event_ids
- connector_runs.errors
- control_mappings.crosswalk_path
- control_results.assertion_findings
- control_results.remediation_steps
- control_results.evidence_ids
- data_silos.scan_findings
- data_silos.applicable_frameworks
- embeddings.vector
- evidence_requests.evidence_ids
- findings.detail
- issues.remediation_evidence
- issues.tags
- personnel.agreements_signed
- personnel.idp_groups
- personnel.training_completions
- personnel.flags
- poams.milestones
- poams.delay_justifications
- posture_snapshots.evidence_sources
- posture_snapshots.sufficiency_details
- questionnaire_templates.questions
- questionnaires.responses
- questionnaires.ai_suggested_answers
- questionnaires.risk_findings
- raw_events.raw_data
- risk_acceptances.conditions
- risk_acceptances.auto_reeval_triggers
- risk_analyses.details
- system_dependencies.shared_controls
- system_profiles.cloud_accounts
- system_profiles.network_boundaries
- system_profiles.interconnections
- system_profiles.connector_scope
- system_profiles.frameworks
- trust_access_requests.document_types
- users.allowed_frameworks
- users.allowed_sources
- users.allowed_control_families
- users.allowed_actions
- users.mfa_backup_codes
