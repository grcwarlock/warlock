/**
 * Typed API endpoint functions organized by domain.
 *
 * Every function calls `api()` from the client module, which handles
 * auth headers, token refresh, and error handling automatically.
 */

import { api } from "@/api/client";
import type {
  AlertConfig,
  AlertData,
  AlertsParams,
  AIConfigureRequest,
  AIConfigureResponse,
  AIModelsList,
  AIStatus,
  Attestation,
  AuditEngagement,
  AuditEntry,
  AuditVerification,
  CadenceData,
  Connector,
  ControlDetail,
  ControlResult,
  Control,
  CoverageData,
  DashboardSummary,
  DriftEvent,
  Finding,
  FindingsParams,
  Framework,
  HashChainVerification,
  Issue,
  IssueDetail,
  IssuesParams,
  IssueSummary,
  OSCALExportRequest,
  PaginatedResponse,
  PipelineStatus,
  PostureData,
  PostureHistory,
  Remediation,
  RemediationsParams,
  ResultsParams,
  RiskAnalysis,
  SufficiencyData,
  VendorRisk,
} from "@/api/types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function toSearchParams(params: Record<string, unknown>): string {
  const sp = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null) {
      sp.set(key, String(value));
    }
  }
  const str = sp.toString();
  return str ? `?${str}` : "";
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

export function getDashboardSummary(): Promise<DashboardSummary> {
  return api<DashboardSummary>("/dashboard/summary");
}

export function getCoverage(framework?: string): Promise<CoverageData[]> {
  const qs = framework ? `?framework=${encodeURIComponent(framework)}` : "";
  return api<CoverageData[]>(`/results/coverage${qs}`);
}

export function getPostureHistory(
  framework: string,
  controlId?: string,
  days?: number,
): Promise<PostureHistory[]> {
  const params: Record<string, unknown> = { framework };
  if (controlId) params.control_id = controlId;
  if (days) params.days = days;
  return api<PostureHistory[]>(`/posture/history${toSearchParams(params)}`);
}

export function getDrift(
  framework?: string,
  days?: number,
  direction?: string,
): Promise<DriftEvent[]> {
  const params: Record<string, unknown> = {};
  if (framework) params.framework = framework;
  if (days) params.days = days;
  if (direction) params.direction = direction;
  return api<DriftEvent[]>(`/drift${toSearchParams(params)}`);
}

export function getCadence(
  framework?: string,
  staleOnly?: boolean,
): Promise<CadenceData[]> {
  const params: Record<string, unknown> = {};
  if (framework) params.framework = framework;
  if (staleOnly) params.stale_only = "true";
  return api<CadenceData[]>(`/cadence${toSearchParams(params)}`);
}

export function getSufficiency(
  framework?: string,
  below?: number,
): Promise<SufficiencyData[]> {
  const params: Record<string, unknown> = {};
  if (framework) params.framework = framework;
  if (below !== undefined) params.below = below;
  return api<SufficiencyData[]>(`/sufficiency${toSearchParams(params)}`);
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

export function getConnectors(): Promise<Connector[]> {
  return api<Connector[]>("/connectors");
}

export function getConnectorStatus(provider: string): Promise<Connector> {
  return api<Connector>(`/connectors/${encodeURIComponent(provider)}/status`);
}

export function getPipelineStatus(): Promise<PipelineStatus> {
  return api<PipelineStatus>("/pipeline/status");
}

export function triggerCollect(
  sources?: string[],
): Promise<{ status: string; run_id: string }> {
  const qs = sources?.length
    ? `?${sources.map((s) => `source=${encodeURIComponent(s)}`).join("&")}`
    : "";
  return api<{ status: string; run_id: string }>(`/pipeline/collect${qs}`, {
    method: "POST",
  });
}

export function verifyHashChain(): Promise<HashChainVerification> {
  return api<HashChainVerification>("/pipeline/verify-chain");
}

// ---------------------------------------------------------------------------
// Compliance
// ---------------------------------------------------------------------------

export function getFrameworks(): Promise<Framework[]> {
  return api<Framework[]>("/frameworks");
}

export function getFrameworkControls(
  frameworkId: string,
  limit?: number,
  offset?: number,
): Promise<Control[]> {
  const params: Record<string, unknown> = {};
  if (limit) params.limit = limit;
  if (offset) params.offset = offset;
  return api<Control[]>(
    `/frameworks/${encodeURIComponent(frameworkId)}/controls${toSearchParams(params)}`,
  );
}

export function getControlDetail(
  controlId: string,
  framework?: string,
): Promise<ControlDetail> {
  const qs = framework
    ? `?framework=${encodeURIComponent(framework)}`
    : "";
  return api<ControlDetail>(`/controls/${encodeURIComponent(controlId)}${qs}`);
}

export function getResults(
  params: ResultsParams = {},
): Promise<PaginatedResponse<ControlResult>> {
  return api<PaginatedResponse<ControlResult>>(
    `/results${toSearchParams(params as Record<string, unknown>)}`,
  );
}

export function getPosture(
  framework?: string,
  controlId?: string,
): Promise<PostureData[]> {
  const params: Record<string, unknown> = {};
  if (framework) params.framework = framework;
  if (controlId) params.control_id = controlId;
  return api<PostureData[]>(`/results/posture${toSearchParams(params)}`);
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

export function getFindings(
  params: FindingsParams = {},
): Promise<PaginatedResponse<Finding>> {
  return api<PaginatedResponse<Finding>>(
    `/findings${toSearchParams(params as Record<string, unknown>)}`,
  );
}

export function getFindingDetail(id: string): Promise<Finding> {
  return api<Finding>(`/findings/${encodeURIComponent(id)}`);
}

// ---------------------------------------------------------------------------
// Remediation
// ---------------------------------------------------------------------------

export function getRemediations(
  params: RemediationsParams = {},
): Promise<PaginatedResponse<Remediation>> {
  return api<PaginatedResponse<Remediation>>(
    `/remediations${toSearchParams(params as Record<string, unknown>)}`,
  );
}

export function getRemediationDetail(id: string): Promise<Remediation> {
  return api<Remediation>(`/remediations/${encodeURIComponent(id)}`);
}

export function createRemediation(body: {
  title: string;
  description?: string;
  framework?: string;
  control_id?: string;
  finding_id?: string;
  due_date?: string;
}): Promise<Remediation> {
  return api<Remediation>("/remediations", {
    method: "POST",
    body,
  });
}

export function transitionRemediation(
  id: string,
  targetStatus: string,
  payload?: Record<string, unknown>,
): Promise<Remediation> {
  const enc = encodeURIComponent(id);
  // Map target status to the correct backend endpoint
  const endpointMap: Record<string, { path: string; method: string }> = {
    assigned: { path: `/remediations/${enc}/assign`, method: "PATCH" },
    in_progress: { path: `/remediations/${enc}/start`, method: "PATCH" },
    pending_verification: { path: `/remediations/${enc}/submit-verification`, method: "PATCH" },
    verification: { path: `/remediations/${enc}/submit-verification`, method: "PATCH" },
    closed: { path: `/remediations/${enc}/verify`, method: "PATCH" },
    verified: { path: `/remediations/${enc}/verify`, method: "PATCH" },
  };
  const ep = endpointMap[targetStatus];
  if (!ep) {
    return Promise.reject(new Error(`Unknown transition target: ${targetStatus}`));
  }
  return api<Remediation>(ep.path, {
    method: ep.method,
    body: payload ?? {},
  });
}

// ---------------------------------------------------------------------------
// Governance — Issues
// ---------------------------------------------------------------------------

export function getIssues(
  params: IssuesParams = {},
): Promise<PaginatedResponse<Issue>> {
  return api<PaginatedResponse<Issue>>(
    `/issues${toSearchParams(params as Record<string, unknown>)}`,
  );
}

export function getIssueDetail(id: string): Promise<IssueDetail> {
  return api<IssueDetail>(`/issues/${encodeURIComponent(id)}`);
}

export function getIssueSummary(): Promise<IssueSummary> {
  return api<IssueSummary>("/issues/summary");
}

export function transitionIssue(
  id: string,
  status: string,
  notes?: string,
): Promise<Issue> {
  return api<Issue>(`/issues/${encodeURIComponent(id)}/transition`, {
    method: "PATCH",
    body: { status, notes },
  });
}

// ---------------------------------------------------------------------------
// Governance — Alerts
// ---------------------------------------------------------------------------

export function getAlerts(
  params: AlertsParams = {},
): Promise<PaginatedResponse<AlertData>> {
  return api<PaginatedResponse<AlertData>>(
    `/alerts${toSearchParams(params as Record<string, unknown>)}`,
  );
}

export function getAlertDetail(id: string): Promise<AlertData> {
  return api<AlertData>(`/alerts/${encodeURIComponent(id)}`);
}

// ---------------------------------------------------------------------------
// Risk
// ---------------------------------------------------------------------------

export function getVendorRisk(
  provider?: string,
  threshold?: number,
): Promise<VendorRisk[]> {
  const params: Record<string, unknown> = {};
  if (provider) params.provider = provider;
  if (threshold !== undefined) params.threshold = threshold;
  return api<VendorRisk[]>(`/vendors/risk${toSearchParams(params)}`);
}

export function analyzeRisk(
  framework: string,
  iterations?: number,
): Promise<RiskAnalysis> {
  return api<RiskAnalysis>("/risk/analyze", {
    method: "POST",
    body: { framework, iterations: iterations ?? 10000 },
  });
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

export function getEngagements(): Promise<AuditEngagement[]> {
  return api<AuditEngagement[]>("/engagements");
}

export function getAuditTrail(
  limit?: number,
  offset?: number,
): Promise<PaginatedResponse<AuditEntry>> {
  const params: Record<string, unknown> = {};
  if (limit) params.limit = limit;
  if (offset) params.offset = offset;
  return api<PaginatedResponse<AuditEntry>>(
    `/audit-trail${toSearchParams(params)}`,
  );
}

export function verifyAuditTrail(): Promise<AuditVerification> {
  return api<AuditVerification>("/audit-trail/verify");
}

export function getAttestations(
  framework?: string,
): Promise<Attestation[]> {
  const qs = framework
    ? `?framework=${encodeURIComponent(framework)}`
    : "";
  return api<Attestation[]>(`/attestations${qs}`);
}

export function exportOscal(
  request: OSCALExportRequest,
): Promise<Record<string, unknown>> {
  return api<Record<string, unknown>>("/export/oscal", {
    method: "POST",
    body: request,
  });
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

export function getUsers(): Promise<UserListResult> {
  return api<UserListResult>("/users");
}

type UserListResult = import("@/api/types").UserResponse[];

export function getAIStatus(): Promise<AIStatus> {
  return api<AIStatus>("/ai/status");
}

export function getAIModels(): Promise<AIModelsList> {
  return api<AIModelsList>("/ai/models");
}

export function configureAI(
  config: AIConfigureRequest,
): Promise<AIConfigureResponse> {
  return api<AIConfigureResponse>("/ai/configure", {
    method: "POST",
    body: config,
  });
}

export function getAlertConfig(): Promise<AlertConfig> {
  return api<AlertConfig>("/alert-config");
}

export function updateAlertConfig(config: AlertConfig): Promise<AlertConfig> {
  return api<AlertConfig>("/alert-config", {
    method: "PUT",
    body: config,
  });
}

// ---------------------------------------------------------------------------
// Re-exports from auth
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Resource Topology
// ---------------------------------------------------------------------------

export function getTopology(
  sourceType?: string,
  provider?: string,
): Promise<import("@/api/types").TopologyResponse> {
  const params: Record<string, unknown> = {};
  if (sourceType) params.source_type = sourceType;
  if (provider) params.provider = provider;
  return api<import("@/api/types").TopologyResponse>(
    `/resources/topology${toSearchParams(params)}`,
  );
}

// ---------------------------------------------------------------------------
// Remediation Command Generator
// ---------------------------------------------------------------------------

export function generateRemediation(
  request: import("@/api/types").RemediationGenerateRequest,
): Promise<import("@/api/types").RemediationGenerateResponse> {
  return api<import("@/api/types").RemediationGenerateResponse>(
    "/remediation/generate",
    { method: "POST", body: request },
  );
}

export { login, logout } from "@/api/auth";
