/**
 * TypeScript types for Warlock API responses.
 *
 * Derived from the FastAPI Pydantic models in warlock/api/routers/.
 * Field names and shapes match the actual JSON the backend returns.
 */

// ---------------------------------------------------------------------------
// Common
// ---------------------------------------------------------------------------

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface ApiErrorResponse {
  detail: string;
}

export interface MessageResponse {
  message: string;
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

export interface LoginRequest {
  email: string;
  password: string;
}

export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  user_id: string;
  role: string;
}

export interface MFARequiredResponse {
  mfa_required: true;
  mfa_token: string;
  message: string;
}

export type LoginResult = LoginResponse | MFARequiredResponse;

export interface UserResponse {
  id: string;
  email: string;
  name: string;
  role: string;
  is_active: boolean;
  allowed_frameworks: string[];
  allowed_sources: string[];
  created_at: string;
  last_login: string | null;
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

export interface DashboardFramework {
  framework: string;
  compliance_rate: number;
  total_controls: number;
  compliant_controls: number;
  non_compliant_controls: number;
  trend: "improving" | "degrading" | "stable";
}

export interface DashboardTopRisk {
  framework: string;
  control_id: string;
  severity: string;
  non_compliant_count: number;
}

export interface DashboardDrift {
  framework: string;
  control_id: string;
  previous_status: string;
  new_status: string;
  drift_direction: string;
  detected_at: string | null;
}

export interface DashboardConnector {
  provider: string;
  source_type: string;
  status: string;
  event_count: number;
  error_count: number;
  started_at: string | null;
  completed_at: string | null;
}

export interface DashboardOpenIssues {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface DashboardSummary {
  frameworks: DashboardFramework[];
  top_risks: DashboardTopRisk[];
  recent_drift: DashboardDrift[];
  open_issues: DashboardOpenIssues;
  posture_score: number;
  connectors: DashboardConnector[];
  last_assessment: string | null;
  generated_at: string;
  cache_ttl_seconds: number;
  ai_narrative?: string | null;
  ai_metadata?: {
    model: string;
    provider: string;
    latency_ms: number;
    confidence: number;
  } | null;
}

// ---------------------------------------------------------------------------
// Compliance — Coverage
// ---------------------------------------------------------------------------

export interface CoverageData {
  framework: string;
  total: number;
  compliant: number;
  non_compliant: number;
  partial: number;
  not_assessed: number;
  rate: number;
}

// ---------------------------------------------------------------------------
// Compliance — Frameworks & Controls
// ---------------------------------------------------------------------------

export interface Framework {
  name: string;
  control_count: number;
}

export interface Control {
  framework: string;
  control_id: string;
  control_family: string | null;
  result_count: number;
}

export interface ControlDetailResource {
  resource_id: string;
  resource_type: string;
  source: string;
  provider: string | null;
  region: string | null;
  severity: string | null;
}

export interface ControlDetailRemediation {
  summary: string | null;
  steps: string[];
  console_path: string | null;
  recommended_reading: string[];
}

export interface ControlDetail {
  control_id: string;
  frameworks: string[];
  description: string | null;
  total_results: number;
  compliant_count: number;
  non_compliant_count: number;
  partial_count: number;
  not_assessed_count: number;
  passing_resources: ControlDetailResource[];
  failing_resources: ControlDetailResource[];
  remediation: ControlDetailRemediation | null;
  ai_remediation: Record<string, unknown> | null;
}

export interface ControlResult {
  id: string;
  framework: string;
  control_id: string;
  status: string;
  severity: string;
  assessor: string;
  assertion_name: string | null;
  assertion_passed: boolean | null;
  assessed_at: string;
  finding_id: string;
  remediation_summary: string | null;
}

// ---------------------------------------------------------------------------
// Compliance — Posture
// ---------------------------------------------------------------------------

export interface PostureData {
  framework: string;
  control_id: string;
  status: string;
  posture_score: number;
  sufficiency_score: number;
  evidence_sources: string[];
  evidence_freshness: number | null;
}

export interface PostureHistoryPoint {
  date: string;
  status: string;
  posture_score: number;
  sufficiency_score: number;
  evidence_freshness_hours: number | null;
}

export interface PostureHistory {
  framework: string;
  control_id: string;
  trend: string;
  trend_slope: number;
  points: PostureHistoryPoint[];
}

// ---------------------------------------------------------------------------
// Compliance — Cadence & Sufficiency
// ---------------------------------------------------------------------------

export interface CadenceData {
  framework: string;
  control_id: string;
  required_frequency: string;
  required_hours: number;
  last_evidence_at: string | null;
  hours_since: number | null;
  is_stale: boolean;
  staleness_ratio: number;
}

export interface SufficiencyData {
  framework: string;
  control_id: string;
  score: number;
  evidence_volume: number;
  evidence_freshness: number;
  evidence_diversity: number;
  assertion_coverage: number;
  gaps: string[];
}

// ---------------------------------------------------------------------------
// Compliance — Drift
// ---------------------------------------------------------------------------

export interface DriftEvent {
  id: string;
  framework: string;
  control_id: string;
  drift_direction: string;
  previous_status: string;
  new_status: string;
  correlated_changes: number;
  detected_at: string | null;
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

export interface Finding {
  id: string;
  title: string;
  observation_type: string;
  severity: string;
  resource_id: string | null;
  resource_type: string | null;
  source: string;
  provider: string;
  observed_at: string;
  detail: unknown;
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

export interface Connector {
  provider: string;
  source_type: string;
  enabled: boolean;
  last_run: string | null;
  last_status: string | null;
}

export interface PipelineLastRun {
  id: string | null;
  status: string | null;
  started_at: string | null;
  completed_at: string | null;
  duration_seconds: number | null;
}

export interface PipelineTotals {
  raw_events: number;
  findings: number;
  control_results: number;
}

export interface PipelineStatus {
  running: boolean;
  last_run: PipelineLastRun | null;
  totals: PipelineTotals;
}

export interface HashChainVerification {
  total: number;
  verified: number;
  broken_at_sequence: number | null;
  verified_at: string;
}

// ---------------------------------------------------------------------------
// Remediation
// ---------------------------------------------------------------------------

export interface Remediation {
  id: string;
  title: string;
  description: string | null;
  finding_id: string | null;
  control_result_id: string | null;
  alert_id: string | null;
  issue_id: string | null;
  framework: string | null;
  control_id: string | null;
  status: string;
  assigned_to: string | null;
  assigned_by: string | null;
  assigned_at: string | null;
  remediation_plan: string | null;
  remediation_steps: Array<Record<string, unknown>> | null;
  evidence: Array<Record<string, unknown>> | null;
  verified_by: string | null;
  verified_at: string | null;
  verification_notes: string | null;
  due_date: string | null;
  closed_at: string | null;
  created_at: string;
  updated_at: string | null;
  created_by: string | null;
}

// ---------------------------------------------------------------------------
// Governance — Issues
// ---------------------------------------------------------------------------

export interface Issue {
  id: string;
  title: string;
  description: string | null;
  finding_id: string | null;
  control_result_id: string | null;
  framework: string | null;
  control_id: string | null;
  status: string;
  priority: string;
  assigned_to: string | null;
  assigned_by: string | null;
  assigned_at: string | null;
  due_date: string | null;
  remediated_at: string | null;
  verified_at: string | null;
  closed_at: string | null;
  risk_accepted: boolean;
  risk_acceptance_owner: string | null;
  risk_acceptance_expiry: string | null;
  risk_acceptance_justification: string | null;
  remediation_plan: string | null;
  remediation_evidence: Array<Record<string, unknown>> | null;
  verification_notes: string | null;
  source: string | null;
  tags: string[] | null;
  created_at: string;
  updated_at: string | null;
  created_by: string | null;
}

export interface IssueComment {
  id: string;
  issue_id: string;
  author: string;
  content: string;
  comment_type: string;
  created_at: string;
}

export interface IssueDetail {
  issue: Issue;
  comments: IssueComment[];
}

export interface IssueSummary {
  total: number;
  by_status: Record<string, number>;
  by_priority: Record<string, number>;
  overdue: number;
}

// ---------------------------------------------------------------------------
// Governance — Audit Engagements
// ---------------------------------------------------------------------------

export interface AuditEngagement {
  id: string;
  name: string;
  framework: string;
  period_start: string;
  period_end: string;
  status: string;
  auditor_name: string | null;
  auditor_firm: string | null;
  in_scope_controls: string[];
  excluded_controls: string[];
  created_at: string;
  completed_at: string | null;
}

// ---------------------------------------------------------------------------
// Governance — Attestations
// ---------------------------------------------------------------------------

export interface Attestation {
  id: string;
  engagement_id: string | null;
  framework: string;
  control_id: string | null;
  status: string;
  statement: string;
  evidence_references: Array<Record<string, unknown>> | null;
  prepared_by: string | null;
  prepared_at: string | null;
  submitted_by: string | null;
  submitted_at: string | null;
  reviewed_by: string | null;
  reviewed_at: string | null;
  review_notes: string | null;
  approved_by: string | null;
  approved_at: string | null;
  rejected_by: string | null;
  rejected_at: string | null;
  rejection_reason: string | null;
  created_at: string;
  updated_at: string | null;
}

// ---------------------------------------------------------------------------
// Audit Trail
// ---------------------------------------------------------------------------

export interface AuditEntry {
  id: string;
  sequence: number;
  action: string;
  entity_type: string;
  entity_id: string;
  actor: string;
  entry_hash: string;
  previous_hash: string;
  created_at: string;
}

export interface AuditVerification {
  valid: boolean;
  total_entries: number;
  errors: string[];
}

// ---------------------------------------------------------------------------
// Risk
// ---------------------------------------------------------------------------

export interface RiskScenario {
  name: string;
  mean_ale: number;
  var_95: number;
  var_99: number;
  control_effectiveness: number;
}

export interface RiskPortfolio {
  total_mean_ale: number;
  total_var_95: number;
  total_var_99: number;
  scenario_count: number;
  iterations: number;
}

export interface RiskAnalysis {
  framework: string;
  scenarios: RiskScenario[];
  portfolio: RiskPortfolio;
  ai_narrative?: string | null;
  ai_metadata?: {
    model: string;
    provider: string;
    latency_ms: number;
    confidence: number;
  } | null;
}

export interface VendorRisk {
  vendor_name: string;
  vendor_id: string;
  overall_score: number;
  risk_level: string;
  issues_count: number;
  criticality_score: number;
  security_posture_score: number;
  assessment_currency_score: number;
  sla_compliance_score: number;
  recommendations: string[];
}

// ---------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------

export interface AlertData {
  id: string;
  title: string;
  description: string | null;
  severity: string;
  category: string;
  finding_id: string | null;
  control_result_id: string | null;
  connector_name: string | null;
  framework: string | null;
  control_id: string | null;
  mitre_tactic: string | null;
  mitre_technique: string | null;
  status: string;
  acknowledged_by: string | null;
  acknowledged_at: string | null;
  resolved_by: string | null;
  resolved_at: string | null;
  resolution_notes: string | null;
  rule_name: string | null;
  rule_metadata: Record<string, unknown> | null;
  triggered_at: string;
  created_at: string;
  updated_at: string | null;
}

// ---------------------------------------------------------------------------
// Settings — AI
// ---------------------------------------------------------------------------

export interface AIStatus {
  ai_enabled: boolean;
  provider: string;
  model: string;
  healthy: boolean;
  last_call: Record<string, unknown> | null;
}

export interface AIConfigureRequest {
  provider: string;
  api_key: string;
  base_url?: string;
}

export interface AIConfigureResponse {
  provider: string;
  connected: boolean;
  available_models: AIModel[];
}

export interface AIModel {
  id: string;
  display_name: string;
  verified: boolean;
}

export interface AIModelsList {
  provider: string;
  connected: boolean;
  models: AIModel[];
}

// ---------------------------------------------------------------------------
// Settings — Alert Config
// ---------------------------------------------------------------------------

export interface AlertConfig {
  alert_rules: Array<Record<string, unknown>>;
}

// ---------------------------------------------------------------------------
// OSCAL Export
// ---------------------------------------------------------------------------

export interface OSCALExportRequest {
  export_type: "ar" | "ssp" | "poam";
  framework?: string;
  system_name?: string;
  description?: string;
}

// ---------------------------------------------------------------------------
// Query parameter types
// ---------------------------------------------------------------------------

export interface FindingsParams {
  framework?: string;
  severity?: string;
  observation_type?: string;
  source?: string;
  provider?: string;
  resource_type?: string;
  date_from?: string;
  date_to?: string;
  limit?: number;
  offset?: number;
}

export interface ResultsParams {
  framework?: string;
  control_id?: string;
  status?: string;
  severity?: string;
  assessor?: string;
  date_from?: string;
  date_to?: string;
  limit?: number;
  offset?: number;
}

export interface IssuesParams {
  status?: string;
  priority?: string;
  framework?: string;
  assigned_to?: string;
  limit?: number;
  offset?: number;
}

export interface RemediationsParams {
  status?: string;
  assigned_to?: string;
  framework?: string;
  limit?: number;
  offset?: number;
}

export interface AlertsParams {
  status?: string;
  severity?: string;
  category?: string;
  framework?: string;
  limit?: number;
  offset?: number;
}
