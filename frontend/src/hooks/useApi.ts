/**
 * TanStack Query hooks wrapping every API endpoint function.
 *
 * Each hook returns a UseQueryResult or UseMutationResult with
 * proper typing. Query keys are namespaced by domain for easy
 * invalidation.
 */

import {
  useQuery,
  useMutation,
  type UseQueryOptions,
} from "@tanstack/react-query";
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
  UserResponse,
  VendorRisk,
} from "@/api/types";
import {
  getDashboardSummary,
  getCoverage,
  getPostureHistory,
  getDrift,
  getCadence,
  getSufficiency,
  getConnectors,
  getConnectorStatus,
  getPipelineStatus,
  triggerCollect,
  verifyHashChain,
  getFrameworks,
  getFrameworkControls,
  getControlDetail,
  getResults,
  getPosture,
  getFindings,
  getFindingDetail,
  getRemediations,
  getRemediationDetail,
  createRemediation,
  transitionRemediation,
  getIssues,
  getIssueDetail,
  getIssueSummary,
  transitionIssue,
  getAlerts,
  getAlertDetail,
  getVendorRisk,
  analyzeRisk,
  getEngagements,
  getAuditTrail,
  verifyAuditTrail,
  getAttestations,
  exportOscal,
  getUsers,
  getAIStatus,
  getAIModels,
  configureAI,
  getAlertConfig,
  updateAlertConfig,
  getTopology,
  generateRemediation,
} from "@/api/endpoints";

// ---------------------------------------------------------------------------
// Query key factory
// ---------------------------------------------------------------------------

export const queryKeys = {
  dashboard: ["dashboard"] as const,
  coverage: (framework?: string) => ["coverage", framework] as const,
  postureHistory: (framework: string, controlId?: string) =>
    ["posture-history", framework, controlId] as const,
  drift: (framework?: string) => ["drift", framework] as const,
  cadence: (framework?: string) => ["cadence", framework] as const,
  sufficiency: (framework?: string) => ["sufficiency", framework] as const,
  connectors: ["connectors"] as const,
  connectorStatus: (provider: string) => ["connectors", provider] as const,
  pipelineStatus: ["pipeline-status"] as const,
  frameworks: ["frameworks"] as const,
  frameworkControls: (fwId: string) => ["frameworks", fwId, "controls"] as const,
  controlDetail: (ctrlId: string) => ["controls", ctrlId] as const,
  results: (params: ResultsParams) => ["results", params] as const,
  posture: (framework?: string) => ["posture", framework] as const,
  findings: (params: FindingsParams) => ["findings", params] as const,
  findingDetail: (id: string) => ["findings", id] as const,
  remediations: (params: RemediationsParams) => ["remediations", params] as const,
  remediationDetail: (id: string) => ["remediations", id] as const,
  issues: (params: IssuesParams) => ["issues", params] as const,
  issueDetail: (id: string) => ["issues", id] as const,
  issueSummary: ["issues", "summary"] as const,
  alerts: (params: AlertsParams) => ["alerts", params] as const,
  alertDetail: (id: string) => ["alerts", id] as const,
  vendorRisk: ["vendor-risk"] as const,
  engagements: ["engagements"] as const,
  auditTrail: (limit?: number, offset?: number) =>
    ["audit-trail", limit, offset] as const,
  attestations: (framework?: string) => ["attestations", framework] as const,
  users: ["users"] as const,
  aiStatus: ["ai-status"] as const,
  aiModels: ["ai-models"] as const,
  alertConfig: ["alert-config"] as const,
  hashChain: ["hash-chain"] as const,
  auditVerification: ["audit-verification"] as const,
} as const;

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

export function useDashboardSummary(
  options?: Partial<UseQueryOptions<DashboardSummary>>,
) {
  return useQuery({
    queryKey: queryKeys.dashboard,
    queryFn: getDashboardSummary,
    refetchInterval: 30_000, // GAP-091: live dashboard polling every 30s
    ...options,
  });
}

export function useCoverage(framework?: string) {
  return useQuery({
    queryKey: queryKeys.coverage(framework),
    queryFn: () => getCoverage(framework),
    refetchInterval: 30_000, // GAP-091: live dashboard polling every 30s
  });
}

export function usePostureHistory(framework: string, controlId?: string, days?: number) {
  return useQuery({
    queryKey: queryKeys.postureHistory(framework, controlId),
    queryFn: () => getPostureHistory(framework, controlId, days),
  });
}

export function useDrift(framework?: string, days?: number, direction?: string) {
  return useQuery({
    queryKey: queryKeys.drift(framework),
    queryFn: () => getDrift(framework, days, direction),
  });
}

export function useCadence(framework?: string, staleOnly?: boolean) {
  return useQuery({
    queryKey: queryKeys.cadence(framework),
    queryFn: () => getCadence(framework, staleOnly),
  });
}

export function useSufficiency(framework?: string, below?: number) {
  return useQuery({
    queryKey: queryKeys.sufficiency(framework),
    queryFn: () => getSufficiency(framework, below),
  });
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

export function useConnectors() {
  return useQuery({
    queryKey: queryKeys.connectors,
    queryFn: getConnectors,
  });
}

export function useConnectorStatus(provider: string) {
  return useQuery({
    queryKey: queryKeys.connectorStatus(provider),
    queryFn: () => getConnectorStatus(provider),
  });
}

export function usePipelineStatus() {
  return useQuery({
    queryKey: queryKeys.pipelineStatus,
    queryFn: getPipelineStatus,
    refetchInterval: 5000,
  });
}

export function useTriggerCollect() {
  return useMutation({
    mutationFn: (sources?: string[]) => triggerCollect(sources),
  });
}

export function useVerifyHashChain() {
  return useQuery({
    queryKey: queryKeys.hashChain,
    queryFn: verifyHashChain,
    enabled: false,
  });
}

// ---------------------------------------------------------------------------
// Compliance
// ---------------------------------------------------------------------------

export function useFrameworks() {
  return useQuery({
    queryKey: queryKeys.frameworks,
    queryFn: getFrameworks,
  });
}

export function useFrameworkControls(frameworkId: string) {
  return useQuery({
    queryKey: queryKeys.frameworkControls(frameworkId),
    queryFn: () => getFrameworkControls(frameworkId),
    enabled: !!frameworkId,
  });
}

export function useControlDetail(controlId: string, framework?: string) {
  return useQuery({
    queryKey: queryKeys.controlDetail(controlId),
    queryFn: () => getControlDetail(controlId, framework),
    enabled: !!controlId,
  });
}

export function useResults(params: ResultsParams = {}) {
  return useQuery({
    queryKey: queryKeys.results(params),
    queryFn: () => getResults(params),
  });
}

export function usePosture(framework?: string, controlId?: string) {
  return useQuery({
    queryKey: queryKeys.posture(framework),
    queryFn: () => getPosture(framework, controlId),
  });
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

export function useFindings(params: FindingsParams = {}) {
  return useQuery({
    queryKey: queryKeys.findings(params),
    queryFn: () => getFindings(params),
  });
}

export function useFindingDetail(id: string) {
  return useQuery({
    queryKey: queryKeys.findingDetail(id),
    queryFn: () => getFindingDetail(id),
    enabled: !!id,
  });
}

// ---------------------------------------------------------------------------
// Remediation
// ---------------------------------------------------------------------------

export function useRemediations(params: RemediationsParams = {}) {
  return useQuery({
    queryKey: queryKeys.remediations(params),
    queryFn: () => getRemediations(params),
  });
}

export function useRemediationDetail(id: string) {
  return useQuery({
    queryKey: queryKeys.remediationDetail(id),
    queryFn: () => getRemediationDetail(id),
    enabled: !!id,
  });
}

export function useTransitionRemediation() {
  return useMutation({
    mutationFn: ({
      id,
      targetStatus,
      payload,
    }: {
      id: string;
      targetStatus: string;
      payload?: Record<string, unknown>;
    }) => transitionRemediation(id, targetStatus, payload),
  });
}

export function useCreateRemediation() {
  return useMutation({
    mutationFn: (body: {
      title: string;
      description?: string;
      framework?: string;
      control_id?: string;
      finding_id?: string;
      due_date?: string;
    }) => createRemediation(body),
  });
}

// ---------------------------------------------------------------------------
// Issues
// ---------------------------------------------------------------------------

export function useIssues(params: IssuesParams = {}) {
  return useQuery({
    queryKey: queryKeys.issues(params),
    queryFn: () => getIssues(params),
  });
}

export function useIssueDetail(id: string) {
  return useQuery({
    queryKey: queryKeys.issueDetail(id),
    queryFn: () => getIssueDetail(id),
    enabled: !!id,
  });
}

export function useIssueSummary() {
  return useQuery({
    queryKey: queryKeys.issueSummary,
    queryFn: getIssueSummary,
  });
}

export function useTransitionIssue() {
  return useMutation({
    mutationFn: ({
      id,
      status,
      notes,
    }: {
      id: string;
      status: string;
      notes?: string;
    }) => transitionIssue(id, status, notes),
  });
}

// ---------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------

export function useAlerts(params: AlertsParams = {}) {
  return useQuery({
    queryKey: queryKeys.alerts(params),
    queryFn: () => getAlerts(params),
  });
}

export function useAlertDetail(id: string) {
  return useQuery({
    queryKey: queryKeys.alertDetail(id),
    queryFn: () => getAlertDetail(id),
    enabled: !!id,
  });
}

// ---------------------------------------------------------------------------
// Risk
// ---------------------------------------------------------------------------

export function useVendorRisk(provider?: string, threshold?: number) {
  return useQuery({
    queryKey: queryKeys.vendorRisk,
    queryFn: () => getVendorRisk(provider, threshold),
  });
}

export function useAnalyzeRisk() {
  return useMutation({
    mutationFn: ({
      framework,
      iterations,
    }: {
      framework: string;
      iterations?: number;
    }) => analyzeRisk(framework, iterations),
  });
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

export function useEngagements() {
  return useQuery({
    queryKey: queryKeys.engagements,
    queryFn: getEngagements,
  });
}

export function useAuditTrail(limit?: number, offset?: number) {
  return useQuery({
    queryKey: queryKeys.auditTrail(limit, offset),
    queryFn: () => getAuditTrail(limit, offset),
  });
}

export function useVerifyAuditTrail() {
  return useQuery({
    queryKey: queryKeys.auditVerification,
    queryFn: verifyAuditTrail,
    enabled: false,
  });
}

export function useAttestations(framework?: string) {
  return useQuery({
    queryKey: queryKeys.attestations(framework),
    queryFn: () => getAttestations(framework),
  });
}

export function useExportOscal() {
  return useMutation({
    mutationFn: (request: OSCALExportRequest) => exportOscal(request),
  });
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

export function useUsers() {
  return useQuery({
    queryKey: queryKeys.users,
    queryFn: getUsers,
  });
}

export function useAIStatus() {
  return useQuery({
    queryKey: queryKeys.aiStatus,
    queryFn: getAIStatus,
  });
}

export function useAIModels() {
  return useQuery({
    queryKey: queryKeys.aiModels,
    queryFn: getAIModels,
  });
}

export function useConfigureAI() {
  return useMutation({
    mutationFn: (config: AIConfigureRequest) => configureAI(config),
  });
}

export function useAlertConfig() {
  return useQuery({
    queryKey: queryKeys.alertConfig,
    queryFn: getAlertConfig,
  });
}

export function useUpdateAlertConfig() {
  return useMutation({
    mutationFn: (config: AlertConfig) => updateAlertConfig(config),
  });
}

// ---------------------------------------------------------------------------
// Resource Topology
// ---------------------------------------------------------------------------

export function useTopology(sourceType?: string, provider?: string) {
  return useQuery({
    queryKey: ["topology", sourceType, provider] as const,
    queryFn: () => getTopology(sourceType, provider),
  });
}

// ---------------------------------------------------------------------------
// Remediation Command Generator
// ---------------------------------------------------------------------------

export function useGenerateRemediation() {
  return useMutation({
    mutationFn: (request: import("@/api/types").RemediationGenerateRequest) =>
      generateRemediation(request),
  });
}
