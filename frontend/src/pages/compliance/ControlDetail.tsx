import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  ArrowLeft,
  ShieldCheck,
  FileText,
  Clock,
  ArrowRight,
  Info,
  Sparkles,
  CheckCircle2,
  XCircle,
} from "lucide-react";
import {
  useControlDetail,
  useResults,
  usePostureHistory,
} from "@/hooks/useApi";
import { StatusBadge } from "@/components/shared/StatusBadge";
import { SeverityBadge } from "@/components/shared/SeverityBadge";
import { CodeBlock } from "@/components/shared/CodeBlock";
import { CardSkeleton, LoadingState } from "@/components/shared/LoadingState";
import { EmptyState } from "@/components/shared/EmptyState";
import type { ControlResult, PostureHistoryPoint } from "@/api/types";

// ---------------------------------------------------------------------------
// Assessment tier badge
// ---------------------------------------------------------------------------

const TIER_CONFIG: Record<
  string,
  { label: string; tier: string; style: string }
> = {
  assertion: {
    label: "Tier 1: Assertion",
    tier: "1",
    style: "bg-blue-500/10 text-blue-400 border-blue-500/20",
  },
  ai: {
    label: "Tier 2: AI",
    tier: "2",
    style: "bg-purple-500/10 text-purple-400 border-purple-500/20",
  },
  opa: {
    label: "Tier 3: OPA",
    tier: "3",
    style: "bg-cyan-500/10 text-cyan-400 border-cyan-500/20",
  },
  inherited: {
    label: "Tier 4: Inherited",
    tier: "4",
    style: "bg-zinc-500/10 text-zinc-400 border-zinc-500/20",
  },
};

function TierBadge({ method }: { method: string }) {
  const normalized = method.toLowerCase();
  const config = TIER_CONFIG[normalized] ?? TIER_CONFIG.assertion;
  return (
    <span
      className={`inline-flex items-center rounded-md border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide ${config.style}`}
    >
      {config.label}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Section wrapper
// ---------------------------------------------------------------------------

function Section({
  title,
  icon: Icon,
  children,
}: {
  title: string;
  icon: React.ComponentType<{ className?: string }>;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900 overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-3 border-b border-zinc-800">
        <Icon className="h-4 w-4 text-zinc-500" />
        <h2 className="text-sm font-medium text-zinc-300">{title}</h2>
      </div>
      <div className="p-4">{children}</div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Assessment details panel
// ---------------------------------------------------------------------------

function AssessmentPanel({ results }: { results: ControlResult[] }) {
  if (results.length === 0) {
    return (
      <p className="text-sm text-zinc-500">
        No assessment results available for this control.
      </p>
    );
  }

  // Group by assessor type for display
  const assertions = results.filter((r) => r.assessor === "assertion");
  const aiResults = results.filter((r) => r.assessor === "ai");
  const opaResults = results.filter((r) => r.assessor === "opa");
  const inherited = results.filter(
    (r) => r.assessor !== "assertion" && r.assessor !== "ai" && r.assessor !== "opa"
  );

  return (
    <div className="space-y-4">
      {assertions.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-xs font-medium text-zinc-500 uppercase tracking-wide">
            Assertions
          </h3>
          {assertions.map((r) => (
            <div
              key={r.id}
              className="flex items-center gap-3 rounded-lg bg-zinc-800/40 px-3 py-2"
            >
              {r.assertion_passed ? (
                <CheckCircle2 className="h-4 w-4 text-green-400 shrink-0" />
              ) : (
                <XCircle className="h-4 w-4 text-red-400 shrink-0" />
              )}
              <span className="text-sm text-zinc-300 font-mono">
                {r.assertion_name ?? "unnamed"}
              </span>
              <StatusBadge status={r.status} className="ml-auto" />
            </div>
          ))}
        </div>
      )}

      {aiResults.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-xs font-medium text-zinc-500 uppercase tracking-wide">
            AI Assessment
          </h3>
          {aiResults.map((r) => (
            <div
              key={r.id}
              className="rounded-lg bg-zinc-800/40 px-3 py-2 space-y-1"
            >
              <div className="flex items-center gap-2">
                <Sparkles className="h-3.5 w-3.5 text-purple-400" />
                <StatusBadge status={r.status} />
              </div>
              {r.remediation_summary && (
                <p className="text-xs text-zinc-400 mt-1">
                  {r.remediation_summary}
                </p>
              )}
            </div>
          ))}
        </div>
      )}

      {opaResults.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-xs font-medium text-zinc-500 uppercase tracking-wide">
            OPA Policy Evaluation
          </h3>
          {opaResults.map((r) => (
            <div
              key={r.id}
              className="flex items-center gap-3 rounded-lg bg-zinc-800/40 px-3 py-2"
            >
              <StatusBadge status={r.status} />
              <span className="text-xs text-zinc-400">{r.severity} severity</span>
            </div>
          ))}
        </div>
      )}

      {inherited.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-xs font-medium text-zinc-500 uppercase tracking-wide">
            Other / Inherited
          </h3>
          {inherited.map((r) => (
            <div
              key={r.id}
              className="flex items-center gap-3 rounded-lg bg-zinc-800/40 px-3 py-2"
            >
              <span className="text-sm text-zinc-400">{r.assessor}</span>
              <StatusBadge status={r.status} className="ml-auto" />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Evidence panel
// ---------------------------------------------------------------------------

function EvidencePanel({
  results,
  frameworkId,
}: {
  results: ControlResult[];
  frameworkId: string;
}) {
  // De-duplicate findings from results
  const seen = new Set<string>();
  const findings = results
    .filter((r) => {
      if (!r.finding_id || seen.has(r.finding_id)) return false;
      seen.add(r.finding_id);
      return true;
    })
    .slice(0, 50);

  if (findings.length === 0) {
    return (
      <p className="text-sm text-zinc-500">
        No evidence findings linked to this control.
      </p>
    );
  }

  return (
    <div className="space-y-1">
      {findings.map((r) => (
        <Link
          key={r.finding_id}
          to={`/findings/${encodeURIComponent(r.finding_id)}`}
          className="flex items-center gap-3 rounded-lg px-3 py-2 hover:bg-zinc-800/40 transition-colors"
        >
          <span className="font-mono text-xs text-zinc-400 truncate flex-1 min-w-0">
            {r.finding_id}
          </span>
          <SeverityBadge severity={r.severity} />
          <span className="text-[10px] text-zinc-600 shrink-0">
            {new Date(r.assessed_at).toLocaleDateString()}
          </span>
        </Link>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Crosswalks panel
// ---------------------------------------------------------------------------

function CrosswalksPanel({
  frameworks,
  controlId,
  currentFramework,
}: {
  frameworks: string[];
  controlId: string;
  currentFramework: string;
}) {
  const otherFrameworks = frameworks.filter((f) => f !== currentFramework);

  if (otherFrameworks.length === 0) {
    return (
      <div className="flex items-start gap-2 text-sm text-zinc-500">
        <Info className="h-4 w-4 shrink-0 mt-0.5" />
        <span>Crosswalk data coming soon. This control is currently only mapped to {currentFramework}.</span>
      </div>
    );
  }

  return (
    <div className="space-y-1">
      {otherFrameworks.map((fw) => (
        <Link
          key={fw}
          to={`/compliance/${encodeURIComponent(fw)}/${encodeURIComponent(controlId)}`}
          className="flex items-center gap-3 rounded-lg px-3 py-2 hover:bg-zinc-800/40 transition-colors"
        >
          <span className="text-sm text-zinc-300">{fw}</span>
          <ArrowRight className="h-3 w-3 text-zinc-600" />
          <span className="font-mono text-xs text-zinc-400">{controlId}</span>
        </Link>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// History timeline panel
// ---------------------------------------------------------------------------

function HistoryPanel({ points }: { points: PostureHistoryPoint[] }) {
  if (points.length === 0) {
    return (
      <p className="text-sm text-zinc-500">
        No posture history available for this control.
      </p>
    );
  }

  // Show most recent 20 entries
  const recent = points.slice(-20).reverse();

  return (
    <div className="space-y-0">
      {recent.map((point, i) => (
        <div key={`${point.date}-${i}`} className="flex items-center gap-3 py-1.5">
          {/* Timeline dot + line */}
          <div className="relative flex flex-col items-center w-4">
            <div
              className={`h-2 w-2 rounded-full ${
                point.status === "compliant"
                  ? "bg-green-500"
                  : point.status === "non_compliant"
                    ? "bg-red-500"
                    : point.status === "partial"
                      ? "bg-amber-500"
                      : "bg-zinc-600"
              }`}
            />
            {i < recent.length - 1 && (
              <div className="absolute top-3 w-px h-4 bg-zinc-800" />
            )}
          </div>
          <span className="text-[10px] text-zinc-600 w-20 shrink-0">
            {new Date(point.date).toLocaleDateString()}
          </span>
          <StatusBadge status={point.status} />
          <span className="text-xs text-zinc-500">
            score {Math.round(point.posture_score * 100)}%
          </span>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Remediation panel
// ---------------------------------------------------------------------------

function RemediationPanel({
  remediation,
  aiRemediation,
  controlId,
}: {
  remediation: {
    summary: string | null;
    steps: string[];
    console_path: string | null;
    recommended_reading: string[];
  } | null;
  aiRemediation: Record<string, unknown> | null;
  controlId: string;
}) {
  const [activeTab, setActiveTab] = useState<"playbook" | "ai">("playbook");

  const hasPlaybook =
    remediation && (remediation.summary || remediation.steps.length > 0);
  const hasAI = aiRemediation && Object.keys(aiRemediation).length > 0;

  if (!hasPlaybook && !hasAI) {
    return (
      <div className="space-y-3">
        <p className="text-sm text-zinc-500">
          No remediation guidance available yet for this control.
        </p>
        <Link
          to={`/remediation?control_id=${encodeURIComponent(controlId)}`}
          className="inline-flex items-center justify-center rounded-lg border border-zinc-700 bg-zinc-900 px-2.5 py-1 text-sm font-medium text-zinc-300 hover:bg-zinc-800 transition-colors"
        >
          Create POA&M
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Tab buttons */}
      <div className="flex gap-1 rounded-lg bg-zinc-800/50 p-0.5 w-fit">
        <button
          onClick={() => setActiveTab("playbook")}
          className={`px-3 py-1 rounded-md text-xs font-medium transition-colors ${
            activeTab === "playbook"
              ? "bg-zinc-700 text-zinc-200"
              : "text-zinc-500 hover:text-zinc-300"
          }`}
        >
          Playbook
        </button>
        <button
          onClick={() => setActiveTab("ai")}
          className={`px-3 py-1 rounded-md text-xs font-medium transition-colors ${
            activeTab === "ai"
              ? "bg-zinc-700 text-zinc-200"
              : "text-zinc-500 hover:text-zinc-300"
          }`}
        >
          AI Remediation
        </button>
      </div>

      {/* Playbook tab */}
      {activeTab === "playbook" && (
        <div className="space-y-3">
          {remediation?.summary && (
            <p className="text-sm text-zinc-300">{remediation.summary}</p>
          )}
          {remediation?.steps && remediation.steps.length > 0 && (
            <ol className="list-decimal list-inside space-y-1 text-sm text-zinc-400">
              {remediation.steps.map((step, i) => (
                <li key={i}>{step}</li>
              ))}
            </ol>
          )}
          {remediation?.console_path && (
            <CodeBlock
              code={remediation.console_path}
              language="terraform"
            />
          )}
          {remediation?.recommended_reading &&
            remediation.recommended_reading.length > 0 && (
              <div className="space-y-1">
                <h4 className="text-xs text-zinc-500 font-medium">
                  Recommended Reading
                </h4>
                <ul className="list-disc list-inside text-xs text-zinc-400 space-y-0.5">
                  {remediation.recommended_reading.map((link, i) => (
                    <li key={i}>
                      <a
                        href={link}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-blue-400 hover:underline"
                      >
                        {link}
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            )}
        </div>
      )}

      {/* AI tab */}
      {activeTab === "ai" && (
        <div className="space-y-2">
          {hasAI ? (
            <CodeBlock
              code={JSON.stringify(aiRemediation, null, 2)}
              language="json"
            />
          ) : (
            <p className="text-sm text-zinc-500">
              AI-generated remediation not available for this control.
            </p>
          )}
        </div>
      )}

      {/* Create POA&M */}
      <Link
        to={`/remediation?control_id=${encodeURIComponent(controlId)}`}
        className="inline-flex items-center justify-center rounded-lg border border-zinc-700 bg-zinc-900 px-2.5 py-1 text-sm font-medium text-zinc-300 hover:bg-zinc-800 transition-colors w-fit"
      >
        Create POA&M
      </Link>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function ControlDetail() {
  const { frameworkId, controlId } = useParams<{
    frameworkId: string;
    controlId: string;
  }>();

  const decodedFramework = frameworkId ? decodeURIComponent(frameworkId) : "";
  const decodedControl = controlId ? decodeURIComponent(controlId) : "";

  const {
    data: detail,
    isLoading: detailLoading,
    isError: detailError,
  } = useControlDetail(decodedControl, decodedFramework);

  const { data: resultsData, isLoading: resultsLoading } = useResults({
    framework: decodedFramework,
    control_id: decodedControl,
    limit: 200,
  });

  const { data: historyData } = usePostureHistory(
    decodedFramework,
    decodedControl,
    90
  );

  const results = resultsData?.items ?? [];
  const isLoading = detailLoading || resultsLoading;

  // Determine primary assessment method from latest result
  const latestResult = results.length > 0
    ? results.reduce((a, b) => (a.assessed_at > b.assessed_at ? a : b))
    : null;

  const primaryMethod = latestResult?.assessor ?? "assertion";

  // Aggregate status
  const overallStatus =
    detail && detail.non_compliant_count > 0
      ? "non_compliant"
      : detail && detail.partial_count > 0
        ? "partial"
        : detail && detail.compliant_count > 0
          ? "compliant"
          : "not_assessed";

  // Get history points
  const historyPoints: PostureHistoryPoint[] = historyData?.[0]?.points ?? [];

  return (
    <div className="p-6 space-y-6">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm">
        <Link
          to="/compliance"
          className="text-zinc-500 hover:text-zinc-300 transition-colors"
        >
          Frameworks
        </Link>
        <span className="text-zinc-700">/</span>
        <Link
          to={`/compliance/${encodeURIComponent(decodedFramework)}`}
          className="flex items-center gap-1 text-zinc-500 hover:text-zinc-300 transition-colors"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          {decodedFramework}
        </Link>
        <span className="text-zinc-700">/</span>
        <span className="font-mono text-zinc-300">{decodedControl}</span>
      </div>

      {/* Loading */}
      {isLoading && (
        <div className="space-y-4">
          <CardSkeleton />
          <LoadingState rows={8} />
        </div>
      )}

      {/* Error */}
      {!isLoading && detailError && (
        <EmptyState
          icon={ShieldCheck}
          title="Failed to load control"
          description={`Could not retrieve details for ${decodedControl}.`}
        />
      )}

      {/* Content */}
      {!isLoading && !detailError && detail && (
        <>
          {/* Header card */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
            <div className="flex items-start justify-between gap-4">
              <div className="space-y-2">
                <div className="flex items-center gap-3">
                  <h1 className="text-2xl font-bold font-mono text-zinc-100">
                    {detail.control_id}
                  </h1>
                  <span className="inline-flex items-center rounded-md border border-zinc-700 bg-zinc-800 px-2 py-0.5 text-[10px] font-medium text-zinc-400">
                    {decodedFramework}
                  </span>
                </div>
                {detail.description && (
                  <p className="text-sm text-zinc-400 max-w-2xl">
                    {detail.description}
                  </p>
                )}
              </div>
              <div className="flex flex-col items-end gap-2 shrink-0">
                <StatusBadge status={overallStatus} className="text-xs px-3 py-1" />
                <TierBadge method={primaryMethod} />
              </div>
            </div>

            {/* Stats bar */}
            <div className="mt-4 flex items-center gap-6 text-xs text-zinc-400">
              <span>{detail.total_results} total results</span>
              <span className="text-green-400">
                {detail.compliant_count} compliant
              </span>
              <span className="text-red-400">
                {detail.non_compliant_count} non-compliant
              </span>
              <span className="text-amber-400">
                {detail.partial_count} partial
              </span>
              <span className="text-zinc-600">
                {detail.not_assessed_count} not assessed
              </span>
            </div>
          </div>

          {/* Panels grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Assessment details */}
            <Section title="Assessment Details" icon={ShieldCheck}>
              <AssessmentPanel results={results} />
            </Section>

            {/* Evidence */}
            <Section title="Evidence" icon={FileText}>
              <EvidencePanel
                results={results}
                frameworkId={decodedFramework}
              />
            </Section>

            {/* Crosswalks */}
            <Section title="Crosswalks" icon={ArrowRight}>
              <CrosswalksPanel
                frameworks={detail.frameworks}
                controlId={detail.control_id}
                currentFramework={decodedFramework}
              />
            </Section>

            {/* History */}
            <Section title="Posture History" icon={Clock}>
              <HistoryPanel points={historyPoints} />
            </Section>
          </div>

          {/* Remediation - full width */}
          <Section title="Remediation" icon={Sparkles}>
            <RemediationPanel
              remediation={detail.remediation}
              aiRemediation={detail.ai_remediation}
              controlId={detail.control_id}
            />
          </Section>
        </>
      )}
    </div>
  );
}
