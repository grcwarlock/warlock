import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, AlertTriangle, FileJson, Shield, Wrench } from "lucide-react";

import { cn } from "@/lib/utils";
import { SeverityBadge } from "@/components/shared/SeverityBadge";
import { StatusBadge } from "@/components/shared/StatusBadge";
import { CodeBlock } from "@/components/shared/CodeBlock";
import { CardSkeleton, TableSkeleton } from "@/components/shared/LoadingState";
import { EmptyState } from "@/components/shared/EmptyState";
import { useFindingDetail, useResults, useRemediations } from "@/hooks/useApi";
import type { ControlResult, Remediation } from "@/api/types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function relativeTime(iso: string | null | undefined): string {
  if (!iso) return "never";
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

type TabId = "overview" | "raw" | "controls" | "remediation";

// ---------------------------------------------------------------------------
// Tab navigation
// ---------------------------------------------------------------------------

function TabNav({
  active,
  onChange,
  controlCount,
}: {
  active: TabId;
  onChange: (tab: TabId) => void;
  controlCount: number;
}) {
  const tabs: { id: TabId; label: string; icon: React.ReactNode; count?: number }[] = [
    { id: "overview", label: "Overview", icon: <FileJson className="h-3.5 w-3.5" /> },
    { id: "raw", label: "Raw Event", icon: <FileJson className="h-3.5 w-3.5" /> },
    { id: "controls", label: "Controls", icon: <Shield className="h-3.5 w-3.5" />, count: controlCount },
    { id: "remediation", label: "Remediation", icon: <Wrench className="h-3.5 w-3.5" /> },
  ];

  return (
    <div className="flex items-center gap-1 border-b border-zinc-800 pb-px">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          onClick={() => onChange(tab.id)}
          className={cn(
            "inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium transition-colors rounded-t-md",
            active === tab.id
              ? "text-zinc-100 border-b-2 border-indigo-500 -mb-px"
              : "text-zinc-500 hover:text-zinc-300"
          )}
        >
          {tab.icon}
          {tab.label}
          {tab.count != null && tab.count > 0 && (
            <span className="text-[10px] bg-zinc-800 text-zinc-400 rounded-full px-1.5 py-0.5">
              {tab.count}
            </span>
          )}
        </button>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Tab: Overview
// ---------------------------------------------------------------------------

function OverviewTab({ finding }: { finding: NonNullable<ReturnType<typeof useFindingDetail>["data"]> }) {
  const rows: [string, React.ReactNode][] = [
    ["Finding ID", <span className="font-mono text-zinc-300">{finding.id}</span>],
    ["Title", <span className="text-zinc-200">{finding.title}</span>],
    ["Severity", <SeverityBadge severity={finding.severity} />],
    ["Provider", <span className="text-zinc-300">{finding.provider}</span>],
    ["Source", <span className="text-zinc-300">{finding.source}</span>],
    ["Observation Type", <span className="text-zinc-300">{finding.observation_type}</span>],
    ["Resource ID", finding.resource_id
      ? <span className="font-mono text-zinc-300">{finding.resource_id}</span>
      : <span className="text-zinc-600">N/A</span>],
    ["Resource Type", finding.resource_type
      ? <span className="text-zinc-300">{finding.resource_type}</span>
      : <span className="text-zinc-600">N/A</span>],
    ["Observed At", <span className="text-zinc-300">{relativeTime(finding.observed_at)}</span>],
  ];

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
      <table className="w-full text-sm">
        <tbody>
          {rows.map(([label, value]) => (
            <tr key={label} className="border-b border-zinc-800/50 last:border-0">
              <td className="py-2.5 pr-4 text-zinc-500 font-medium w-40 align-top">{label}</td>
              <td className="py-2.5">{value}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Tab: Raw Event
// ---------------------------------------------------------------------------

function RawEventTab({ detail }: { detail: unknown }) {
  const json = useMemo(() => {
    try {
      return JSON.stringify(detail, null, 2);
    } catch {
      return "{}";
    }
  }, [detail]);

  return <CodeBlock code={json} language="json" />;
}

// ---------------------------------------------------------------------------
// Tab: Controls
// ---------------------------------------------------------------------------

function ControlsTab({ results }: { results: ControlResult[] }) {
  if (results.length === 0) {
    return (
      <EmptyState
        icon={Shield}
        title="No mapped controls"
        description="No control results are linked to this finding."
      />
    );
  }

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900 overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-zinc-800 text-zinc-500 bg-zinc-900/80">
              <th className="text-left py-2.5 px-3 font-medium">Control</th>
              <th className="text-left py-2.5 px-3 font-medium">Framework</th>
              <th className="text-left py-2.5 px-3 font-medium">Status</th>
              <th className="text-left py-2.5 px-3 font-medium">Severity</th>
              <th className="text-left py-2.5 px-3 font-medium">Assessor</th>
              <th className="text-left py-2.5 px-3 font-medium">Assertion</th>
              <th className="text-right py-2.5 px-3 font-medium">Assessed</th>
            </tr>
          </thead>
          <tbody>
            {results.map((r) => (
              <tr
                key={r.id}
                className="border-b border-zinc-800/50 hover:bg-zinc-800/30 transition-colors"
              >
                <td className="py-2 px-3">
                  <Link
                    to={`/compliance/${r.framework.toLowerCase().replace(/[\s.]+/g, "_")}/${r.control_id}`}
                    className="font-mono text-zinc-200 hover:text-indigo-400 transition-colors"
                  >
                    {r.control_id}
                  </Link>
                </td>
                <td className="py-2 px-3 text-zinc-400">{r.framework}</td>
                <td className="py-2 px-3">
                  <StatusBadge status={r.status} />
                </td>
                <td className="py-2 px-3">
                  <SeverityBadge severity={r.severity} />
                </td>
                <td className="py-2 px-3 text-zinc-400">{r.assessor}</td>
                <td className="py-2 px-3">
                  {r.assertion_name ? (
                    <span className="text-zinc-300 font-mono text-[10px]">
                      {r.assertion_name}
                      {r.assertion_passed != null && (
                        <span className={r.assertion_passed ? "text-green-400 ml-1" : "text-red-400 ml-1"}>
                          {r.assertion_passed ? "PASS" : "FAIL"}
                        </span>
                      )}
                    </span>
                  ) : (
                    <span className="text-zinc-600">--</span>
                  )}
                </td>
                <td className="py-2 px-3 text-right text-zinc-500 whitespace-nowrap">
                  {relativeTime(r.assessed_at)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Tab: Remediation
// ---------------------------------------------------------------------------

function RemediationTab({
  remediations,
  isLoading,
}: {
  remediations: Remediation[];
  isLoading: boolean;
}) {
  if (isLoading) return <TableSkeleton rows={3} />;

  if (remediations.length === 0) {
    return (
      <EmptyState
        icon={Wrench}
        title="No remediations"
        description="No remediation playbooks are linked to this finding."
      />
    );
  }

  return (
    <div className="space-y-4">
      {remediations.map((rem) => (
        <div
          key={rem.id}
          className="rounded-xl border border-zinc-800 bg-zinc-900 p-4 space-y-3"
        >
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-medium text-zinc-200">{rem.title}</h3>
            <StatusBadge status={rem.status} />
          </div>

          {rem.description && (
            <p className="text-xs text-zinc-400">{rem.description}</p>
          )}

          {rem.remediation_plan && (
            <div>
              <h4 className="text-[10px] uppercase tracking-wider text-zinc-500 font-medium mb-1.5">
                Remediation Plan
              </h4>
              <p className="text-xs text-zinc-300 leading-relaxed">{rem.remediation_plan}</p>
            </div>
          )}

          {rem.remediation_steps && rem.remediation_steps.length > 0 && (
            <div>
              <h4 className="text-[10px] uppercase tracking-wider text-zinc-500 font-medium mb-1.5">
                Steps
              </h4>
              <div className="space-y-1.5">
                {rem.remediation_steps.map((step, i) => {
                  const stepText =
                    typeof step === "string" ? step : JSON.stringify(step, null, 2);
                  return (
                    <div key={i} className="flex items-start gap-2 text-xs">
                      <span className="text-zinc-500 font-mono shrink-0 w-5 text-right">
                        {i + 1}.
                      </span>
                      <span className="text-zinc-300">{stepText}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Show raw remediation as terraform-like code block if plan looks like IaC */}
          {rem.remediation_plan && rem.remediation_plan.includes("resource") && (
            <CodeBlock
              code={rem.remediation_plan}
              language="terraform"
            />
          )}

          <div className="flex items-center gap-4 text-[10px] text-zinc-500 pt-2 border-t border-zinc-800/50">
            {rem.assigned_to && <span>Assigned: {rem.assigned_to}</span>}
            {rem.due_date && <span>Due: {relativeTime(rem.due_date)}</span>}
            <span>Created: {relativeTime(rem.created_at)}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

export default function FindingDetail() {
  const { findingId } = useParams<{ findingId: string }>();
  const decodedId = findingId ? decodeURIComponent(findingId) : "";

  const [activeTab, setActiveTab] = useState<TabId>("overview");

  const {
    data: finding,
    isLoading: findingLoading,
    isError: findingError,
  } = useFindingDetail(decodedId);

  // Fetch control results that reference this finding
  const { data: resultsResponse } = useResults({
    limit: 500,
  });

  const controlResults: ControlResult[] = useMemo(() => {
    if (!resultsResponse) return [];
    const items = Array.isArray(resultsResponse)
      ? resultsResponse
      : "items" in resultsResponse
        ? resultsResponse.items
        : [];
    return items.filter((r: ControlResult) => r.finding_id === decodedId);
  }, [resultsResponse, decodedId]);

  // Fetch remediations linked to this finding
  const { data: remediationsResponse, isLoading: remLoading } = useRemediations({
    limit: 100,
  });

  const remediations: Remediation[] = useMemo(() => {
    if (!remediationsResponse) return [];
    const items = Array.isArray(remediationsResponse)
      ? remediationsResponse
      : "items" in remediationsResponse
        ? remediationsResponse.items
        : [];
    return items.filter((r: Remediation) => r.finding_id === decodedId);
  }, [remediationsResponse, decodedId]);

  return (
    <div className="p-6 space-y-5 max-w-[1440px] mx-auto">
      {/* Breadcrumb + header */}
      <div>
        <div className="flex items-center gap-1.5 text-xs text-zinc-500 mb-3">
          <Link to="/pipeline" className="hover:text-zinc-300 transition-colors">
            Pipeline
          </Link>
          <span>/</span>
          {finding?.provider && (
            <>
              <Link
                to={`/pipeline/${encodeURIComponent(finding.provider)}`}
                className="hover:text-zinc-300 transition-colors"
              >
                {finding.provider}
              </Link>
              <span>/</span>
            </>
          )}
          <span className="text-zinc-400 truncate max-w-[200px]">{decodedId}</span>
        </div>
        <Link
          to={finding?.provider ? `/pipeline/${encodeURIComponent(finding.provider)}` : "/pipeline"}
          className="inline-flex items-center gap-1 text-xs text-zinc-500 hover:text-zinc-300 transition-colors mb-3"
        >
          <ArrowLeft className="h-3 w-3" />
          Back
        </Link>
      </div>

      {/* Loading */}
      {findingLoading && (
        <div className="space-y-4">
          <CardSkeleton />
          <CardSkeleton />
        </div>
      )}

      {/* Error */}
      {findingError && (
        <EmptyState
          icon={AlertTriangle}
          title="Failed to load finding"
          description={`Could not fetch finding "${decodedId}".`}
        />
      )}

      {/* Content */}
      {finding && !findingLoading && !findingError && (
        <>
          {/* Finding header card */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0">
                <h1 className="text-lg font-semibold text-zinc-100 break-words">
                  {finding.title}
                </h1>
                <div className="flex items-center gap-3 mt-2 flex-wrap">
                  <SeverityBadge severity={finding.severity} />
                  <span className="text-xs text-zinc-500">{finding.provider}</span>
                  <span className="text-xs text-zinc-600">{finding.observation_type}</span>
                  {finding.resource_id && (
                    <span className="text-xs font-mono text-zinc-400">
                      {finding.resource_id}
                    </span>
                  )}
                </div>
              </div>
              <div className="text-xs text-zinc-500 shrink-0 text-right">
                <div>{relativeTime(finding.observed_at)}</div>
                <div className="text-[10px] text-zinc-600 mt-0.5">
                  {controlResults.length} controls mapped
                </div>
              </div>
            </div>
          </div>

          {/* Tab navigation */}
          <TabNav
            active={activeTab}
            onChange={setActiveTab}
            controlCount={controlResults.length}
          />

          {/* Tab content */}
          {activeTab === "overview" && <OverviewTab finding={finding} />}
          {activeTab === "raw" && <RawEventTab detail={finding.detail} />}
          {activeTab === "controls" && <ControlsTab results={controlResults} />}
          {activeTab === "remediation" && (
            <RemediationTab remediations={remediations} isLoading={remLoading} />
          )}
        </>
      )}
    </div>
  );
}
